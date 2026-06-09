import crypto from 'crypto';
import fetch from 'node-fetch';

// ─── MapSis API ───────────────────────────────────────────────────────────────

async function callMapsis(method, params = {}) {
  const { MAPSIS_URL, MAPSIS_USER, MAPSIS_PASS, MAPSIS_KEY } = process.env;

  const url = new URL(`${MAPSIS_URL.replace(/\/$/, '')}/api/mapsis/${method}.asp`);
  url.searchParams.set('usuario', MAPSIS_USER);
  url.searchParams.set('senha', MAPSIS_PASS);
  url.searchParams.set('chave', MAPSIS_KEY);
  url.searchParams.set('encode', 'true');

  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') {
      url.searchParams.set(k, String(v));
    }
  }

  // Log da URL sem expor credenciais
  const safeUrl = url.toString()
    .replace(/(usuario=)[^&]*/, '$1***')
    .replace(/(senha=)[^&]*/, '$1***')
    .replace(/(chave=)[^&]*/, '$1***');
  console.log(`[MapSis] → ${method} | ${safeUrl}`);

  const res = await fetch(url.toString(), {
    headers: { Accept: 'application/json, text/plain, */*' },
  });
  const text = await res.text();
  console.log(`[MapSis] ← ${method} | status=${res.status} | body=${text.slice(0, 800)}`);
  try { return JSON.parse(text); } catch { return { raw: text }; }
}

// ─── Encryption ──────────────────────────────────────────────────────────────

function decryptRequest(body) {
  const raw = process.env.WHATSAPP_PRIVATE_KEY;
  // Remove aspas que usuários colam acidentalmente ("-----BEGIN..." → -----BEGIN...)
  // e normaliza \n literais (formato de linha única) para quebras reais
  const cleaned = raw?.replace(/^["']|["']$/g, '');
  const privateKey = cleaned?.includes('\\n') ? cleaned.replace(/\\n/g, '\n') : cleaned;

  // Dev mode: sem chave configurada → body chega como JSON puro
  if (!privateKey || !body.encrypted_flow_data) {
    return { decrypted: body, aesKey: null, iv: null };
  }

  const aesKey = crypto.privateDecrypt(
    { key: privateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    Buffer.from(body.encrypted_aes_key, 'base64')
  );

  const iv = Buffer.from(body.initial_vector, 'base64');
  const encBuf = Buffer.from(body.encrypted_flow_data, 'base64');
  const encBody = encBuf.subarray(0, -16);
  const authTag = encBuf.subarray(-16);

  const decipher = crypto.createDecipheriv('aes-128-gcm', aesKey, iv);
  decipher.setAuthTag(authTag);

  const decrypted = JSON.parse(
    Buffer.concat([decipher.update(encBody), decipher.final()]).toString('utf8')
  );

  return { decrypted, aesKey, iv };
}

// Retorna o base64 cru da resposta criptografada (string), ou null em modo dev
// (sem chave). O WhatsApp Flows espera o base64 como texto puro no body — NÃO JSON.
function encryptResponse(data, aesKey, iv) {
  if (!aesKey || !iv) return null;

  const flippedIV = Buffer.from(iv.map(b => ~b & 0xff));
  const cipher = crypto.createCipheriv('aes-128-gcm', aesKey, flippedIV);
  const encrypted = Buffer.concat([
    cipher.update(JSON.stringify(data), 'utf8'),
    cipher.final(),
  ]);
  return Buffer.concat([encrypted, cipher.getAuthTag()]).toString('base64');
}

// Envia a resposta no formato que o WhatsApp Flows exige:
// - Com criptografia: base64 puro, Content-Type text/plain
// - Modo dev (sem chave): JSON normal para facilitar testes locais
function sendFlowResponse(res, data, aesKey, iv) {
  const encrypted = encryptResponse(data, aesKey, iv);
  if (encrypted) return res.type('text/plain').send(encrypted);
  return res.json(data);
}

// ─── Normalizers ─────────────────────────────────────────────────────────────

function normalizeLojas(result) {
  const raw = result?.lojas || result?.Lojas || result?.loja || [];
  const all = (Array.isArray(raw) ? raw : [raw])
    .filter(l => l && (l.id_loja_mapsis || l.id || l.cod_loja));

  // Mesmo filtro do PWA: só Tatuapé e João Dias (com fallback para todas)
  const filtradas = all.filter(l => {
    const nome = String(l.nome ?? l.nome_loja ?? '').toUpperCase();
    return nome.includes('TATUAP') || (nome.includes('JO') && nome.includes('DIAS'));
  });
  const lista = filtradas.length > 0 ? filtradas : all;

  console.log(`[normalizeLojas] total=${all.length} filtradas=${filtradas.length} → usando=${lista.length}`);

  return lista.map(l => ({
    id: `${l.id_loja_mapsis ?? l.id ?? ''}|${l.cod_loja ?? ''}`,
    title: l.nome || l.nome_loja || 'Concessionária',
  }));
}

function normalizeServicos(result) {
  const raw = result?.servicos || result?.Servicos || result?.servico || [];
  return (Array.isArray(raw) ? raw : [raw])
    .filter(s => s?.id_servico_mapsis)
    .map(s => ({ id: String(s.id_servico_mapsis), title: s.nome || 'Serviço' }));
}

function normalizeTecnicos(result) {
  const raw = result?.boxes || result?.Boxes || result?.consultores || result?.Consultores || [];
  const excluidos = /ENCAIXE|RECALL/i;
  const lista = (Array.isArray(raw) ? raw : [raw])
    .filter(t => t && (t.id_box_mapsis || t.id_consultor_mapsis))
    .filter(t => !excluidos.test(t.nome_produtivo || t.nome || ''))
    .map(t => ({
      id: String(t.id_box_mapsis || t.id_consultor_mapsis),
      title: t.nome_produtivo || t.nome || 'Técnico',
    }));
  return [{ id: '0', title: 'Sem preferência' }, ...lista];
}

function normalizeHorarios(result) {
  const raw = result?.horarios || result?.Horarios || [];
  const seen = new Set();
  return (Array.isArray(raw) ? raw : [raw])
    .map(h => (typeof h === 'string' ? h : h?.horario || h?.hora || '').substring(0, 5))
    .filter(t => t && /^\d{2}:\d{2}$/.test(t) && !seen.has(t) && seen.add(t))
    .map(t => ({ id: t, title: t }));
}

// Mensagem de erro vinda da API MapSis (igual getErroApi do PWA)
function getErroApi(p) {
  const e = p?.retorno?.erro ?? p?.erro ?? p?.error;
  return typeof e === 'string' && e.trim() ? e : null;
}

// Espelha a lógica do PWA: cliente fica em result.cliente (array ou objeto);
// "existe" = array não-vazio OU id_cliente_mapsis na raiz. NÃO compara cpf_cnpj
// (a API pode devolver o documento em formato diferente, com/sem zero à esquerda).
function extractCliente(result) {
  const raw = result?.cliente ?? result?.clientes ?? result?.Cliente ?? [];
  const arr = Array.isArray(raw) ? raw : (raw ? [raw] : []);
  const erro = getErroApi(result);
  const existe = (arr.length > 0 || !!result?.id_cliente_mapsis) && !erro;

  console.log(`[extractCliente] chaves topo=${Object.keys(result || {}).join(',')} | registros=${arr.length} | erro=${erro || '-'} | existe=${existe}`);
  if (arr[0]) {
    console.log(`  cliente[0]: cpf=${JSON.stringify(arr[0].cpf_cnpj)} id=${JSON.stringify(arr[0].id_cliente_mapsis)} nome=${JSON.stringify(arr[0].nome_cliente || arr[0].nome)}`);
  }

  return { existe, cliente: arr[0] || null };
}

function parsePhone(phone = '') {
  const clean = String(phone).replace(/\D/g, '');
  return { ddd: clean.slice(0, 2), numero: clean.slice(2) };
}

// "2024-06-08" → "08/06/2024"
function isoToBr(iso = '') {
  const [y, m, d] = iso.split('-');
  return `${d}/${m}/${y}`;
}

// ─── Screen handlers ──────────────────────────────────────────────────────────

async function handleInit() {
  return { screen: 'IDENTIFICACAO', data: {} };
}

async function handleIdentificacao({ cpf_cnpj }) {
  const doc = cpf_cnpj.replace(/\D/g, '');
  console.log(`[handleIdentificacao] cpf_cnpj recebido=${JSON.stringify(cpf_cnpj)} → normalizado=${JSON.stringify(doc)}`);

  let clienteResult;
  try {
    clienteResult = await callMapsis('get_cliente', { cpf_cnpj: doc });
  } catch (err) {
    console.error(`[handleIdentificacao] erro get_cliente: ${err.message}`);
    return {
      screen: 'IDENTIFICACAO',
      data: { error_messages: { cpf_cnpj: 'Erro ao consultar dados. Tente novamente.' } },
    };
  }

  const { existe, cliente } = extractCliente(clienteResult);

  if (existe) {
    // IMPORTANTE: os veículos vêm na RAIZ do retorno (result.veiculos), não dentro
    // do objeto cliente — exatamente como o PWA lê (clientePayload?.veiculos)
    const veicRaw = clienteResult?.veiculos ?? clienteResult?.veiculo ?? clienteResult?.Veiculo ?? [];
    const veiculos = (Array.isArray(veicRaw) ? veicRaw : [veicRaw])
      .filter(v => v?.id_veiculo_mapsis)
      .map(v => ({
        id: String(v.id_veiculo_mapsis),
        title: `${v.modelo_carro || v.modelo || 'Veiculo'} - ${v.placa || 'S/Placa'}`,
      }));

    console.log(`[handleIdentificacao] cliente encontrado → ${veiculos.length} veículo(s)`);

    return {
      screen: 'SELECAO_VEICULO',
      data: {
        nome_cliente: cliente?.nome_cliente || cliente?.nome || 'Cliente',
        cpf_cnpj: doc,
        id_cliente_mapsis: String(cliente?.id_cliente_mapsis ?? clienteResult?.id_cliente_mapsis ?? ''),
        veiculos: veiculos.length ? veiculos : [{ id: '0', title: 'Nenhum veiculo cadastrado' }],
      },
    };
  }

  // Cliente não encontrado → tela de cadastro
  console.log('[handleIdentificacao] cliente NÃO encontrado → CADASTRO');
  let lojasResult = {};
  try { lojasResult = await callMapsis('get_lojas'); } catch { /* continua */ }

  return {
    screen: 'CADASTRO',
    data: { cpf_cnpj: doc, lojas: normalizeLojas(lojasResult) },
  };
}

async function handleCadastro(data) {
  const {
    cpf_cnpj, nome, email, celular, telefone,
    modelo_veiculo, placa, chassi, ano_fabricacao,
    ano_modelo, km_atual, data_compra, cod_loja,
  } = data;

  const cel = parsePhone(celular);
  const tel = parsePhone(telefone || '');
  // cod_loja vem como "id_loja_mapsis|cod_loja_real"
  // O PWA envia id_loja_mapsis no campo cod_loja do set_cliente (comportamento testado)
  const [idLojaMapsis] = (cod_loja || '').split('|');

  try {
    await callMapsis('set_cliente', {
      cpf_cnpj,
      nome,
      email,
      ddd_celular: cel.ddd,
      celular: cel.numero,
      ddd: tel.ddd,
      telefone: tel.numero,
      modelo_busca: modelo_veiculo,
      modelo_veiculo,
      marca_veiculo: 'Chevrolet',
      placa: placa.toUpperCase().replace(/[^A-Z0-9]/g, ''),
      chassi: chassi || '',
      ano_fab: ano_fabricacao,
      ano_mod: ano_modelo || ano_fabricacao,
      km: km_atual,
      data_compra: data_compra || '',
      cod_loja: idLojaMapsis || cod_loja,
    });
  } catch {
    let lojasResult = {};
    try { lojasResult = await callMapsis('get_lojas'); } catch { /* continua */ }
    return {
      screen: 'CADASTRO',
      data: {
        cpf_cnpj,
        lojas: normalizeLojas(lojasResult),
        error_messages: { nome: 'Erro ao cadastrar. Verifique os dados e tente novamente.' },
      },
    };
  }

  // Re-buscar cliente para obter os IDs gerados
  const clienteResult = await callMapsis('get_cliente', { cpf_cnpj });
  const { cliente } = extractCliente(clienteResult);
  // Veículos vêm na raiz do retorno (igual PWA)
  const veicRaw = clienteResult?.veiculos ?? clienteResult?.veiculo ?? clienteResult?.Veiculo ?? [];
  const veiculos = Array.isArray(veicRaw) ? veicRaw : [veicRaw];
  const primeiroVeiculo = veiculos[0];

  const [servicosResult, lojasResult] = await Promise.all([
    callMapsis('get_servicos'),
    callMapsis('get_lojas'),
  ]);

  return {
    screen: 'SERVICO_LOJA',
    data: {
      cpf_cnpj,
      id_cliente_mapsis: String(cliente?.id_cliente_mapsis || ''),
      id_veiculo_mapsis: String(primeiroVeiculo?.id_veiculo_mapsis || ''),
      servicos: normalizeServicos(servicosResult),
      lojas: normalizeLojas(lojasResult),
    },
  };
}

async function handleSelecaoVeiculo({ cpf_cnpj, id_cliente_mapsis, id_veiculo_mapsis }) {
  const [servicosResult, lojasResult] = await Promise.all([
    callMapsis('get_servicos'),
    callMapsis('get_lojas'),
  ]);

  return {
    screen: 'SERVICO_LOJA',
    data: {
      cpf_cnpj,
      id_cliente_mapsis,
      id_veiculo_mapsis,
      servicos: normalizeServicos(servicosResult),
      lojas: normalizeLojas(lojasResult),
    },
  };
}

async function handleServicosLoja(data) {
  const { cpf_cnpj, id_cliente_mapsis, id_veiculo_mapsis, id_servico_mapsis, loja_selecionada } = data;
  const [id_loja_mapsis, cod_loja] = (loja_selecionada || '').split('|');

  let tecnicosResult = {};
  try {
    tecnicosResult = await callMapsis('get_boxes', { cod_loja, id_loja_mapsis });
  } catch { /* sem técnicos */ }

  return {
    screen: 'DATA_TECNICO',
    data: {
      cpf_cnpj,
      id_cliente_mapsis,
      id_veiculo_mapsis,
      id_servico_mapsis,
      id_loja_mapsis,
      cod_loja,
      tecnicos: normalizeTecnicos(tecnicosResult),
    },
  };
}

async function handleDataTecnico(data) {
  const {
    cpf_cnpj, id_cliente_mapsis, id_veiculo_mapsis,
    id_servico_mapsis, id_loja_mapsis, cod_loja,
    data_agendamento, id_box_mapsis,
  } = data;

  const apiDate = isoToBr(data_agendamento);
  const boxId = id_box_mapsis && id_box_mapsis !== '0' ? id_box_mapsis : '';

  let horariosResult = {};
  try {
    horariosResult = await callMapsis('get_agenda_horario_disponivel', {
      id_veiculo_mapsis,
      id_loja_mapsis,
      id_servico_mapsis,
      data_agendamento: apiDate,
      retorno_consultor: '0',
      ...(boxId ? { id_box_mapsis: boxId } : {}),
    });
  } catch { /* sem horários */ }

  const horarios = normalizeHorarios(horariosResult);

  if (!horarios.length) {
    let tecnicosResult = {};
    try { tecnicosResult = await callMapsis('get_boxes', { cod_loja, id_loja_mapsis }); } catch { /* ok */ }
    return {
      screen: 'DATA_TECNICO',
      data: {
        cpf_cnpj, id_cliente_mapsis, id_veiculo_mapsis,
        id_servico_mapsis, id_loja_mapsis, cod_loja,
        tecnicos: normalizeTecnicos(tecnicosResult),
        error_messages: {
          data_agendamento: 'Nenhum horário disponível nesta data. Tente outra data.',
        },
      },
    };
  }

  return {
    screen: 'SELECAO_HORARIO',
    data: {
      cpf_cnpj, id_cliente_mapsis, id_veiculo_mapsis,
      id_servico_mapsis, id_loja_mapsis, cod_loja,
      id_box_mapsis: id_box_mapsis || '0',
      data_agendamento,
      data_formatada: isoToBr(data_agendamento),
      horarios,
    },
  };
}

async function handleSelecaoHorario(data) {
  const {
    cpf_cnpj, id_cliente_mapsis, id_veiculo_mapsis,
    id_servico_mapsis, id_loja_mapsis, cod_loja,
    id_box_mapsis, data_agendamento, hora_agendamento, observacao,
  } = data;

  return {
    screen: 'CONTATO',
    data: {
      cpf_cnpj, id_cliente_mapsis, id_veiculo_mapsis,
      id_servico_mapsis, id_loja_mapsis, cod_loja,
      id_box_mapsis: id_box_mapsis || '0',
      data_agendamento,
      hora_agendamento,
      observacao: observacao || '',
    },
  };
}

async function handleContato(data) {
  const {
    cpf_cnpj, id_veiculo_mapsis, id_servico_mapsis,
    id_loja_mapsis, cod_loja, id_box_mapsis,
    data_agendamento, hora_agendamento, observacao,
    email, celular, telefone,
  } = data;

  // Buscar dados completos do cliente e do veículo para o agendamento
  let nome_cliente = '', marca_veiculo = 'Chevrolet', modelo_veiculo = '',
    ano_fabricacao = '', ano_modelo = '', km_atual = '', placa = '', chassi = '';

  try {
    const clienteResult = await callMapsis('get_cliente', { cpf_cnpj });
    const { cliente } = extractCliente(clienteResult);
    if (cliente) {
      nome_cliente = cliente.nome_cliente || cliente.nome || '';
      // Veículos na raiz do retorno (igual PWA)
      const veicRaw = clienteResult?.veiculos ?? clienteResult?.veiculo ?? clienteResult?.Veiculo ?? [];
      const veiculos = Array.isArray(veicRaw) ? veicRaw : [veicRaw];
      const veiculo =
        veiculos.find(v => String(v.id_veiculo_mapsis) === String(id_veiculo_mapsis)) ||
        veiculos[0];
      if (veiculo) {
        marca_veiculo = veiculo.marca || 'Chevrolet';
        modelo_veiculo = veiculo.modelo_carro || veiculo.modelo || '';
        ano_fabricacao = String(veiculo.ano_fabricacao || '');
        ano_modelo = String(veiculo.ano_modelo || ano_fabricacao);
        km_atual = String(veiculo.kilometragem_atual || veiculo.km_atual || veiculo.km || '');
        placa = veiculo.placa || '';
        chassi = veiculo.chassis || veiculo.chassi || '';
      }
    }
  } catch { /* agendamento prossegue sem dados completos */ }

  const cel = parsePhone(celular);
  const tel = parsePhone(telefone || '');
  const apiDate = isoToBr(data_agendamento);
  const boxId = id_box_mapsis && id_box_mapsis !== '0' ? id_box_mapsis : '';

  try {
    await callMapsis('set_agendamento', {
      cpf_cnpj,
      nome: nome_cliente,
      email,
      ddd: tel.ddd,
      telefone: tel.numero,
      ddd_celular: cel.ddd,
      celular: cel.numero,
      cod_loja,
      id_loja_mapsis,
      id_servico_mapsis,
      id_veiculo_mapsis,
      ...(boxId ? { id_box: boxId } : {}),
      marca_veiculo,
      modelo_veiculo,
      ano_fabricacao,
      ano_modelo,
      km_atual,
      placa,
      chassi,
      data_agendamento: apiDate,
      hora_agendamento,
      observacao: observacao || '',
      status_agendamento: 'P',
      CalledFrom: 'WHATSAPP_FLOWS_NOVA_CHEVROLET',
      origem: 'WHATSAPP',
      origem_lead: 'WHATSAPP',
      como_chegou: 'WHATSAPP FLOWS',
    });
  } catch {
    return {
      screen: 'CONTATO',
      data: {
        cpf_cnpj,
        id_cliente_mapsis: data.id_cliente_mapsis,
        id_veiculo_mapsis,
        id_servico_mapsis,
        id_loja_mapsis,
        cod_loja,
        id_box_mapsis: id_box_mapsis || '0',
        data_agendamento,
        hora_agendamento,
        observacao: observacao || '',
        email_prefill: email,
        celular_prefill: celular,
        telefone_prefill: telefone || '',
        error_messages: { email: 'Erro ao confirmar o agendamento. Tente novamente.' },
      },
    };
  }

  // Buscar nomes legíveis para o resumo final
  let resumo_loja = cod_loja, resumo_servico = '', resumo_tecnico = 'Sem preferência de técnico';
  try {
    const [lojasResult, servicosResult] = await Promise.all([
      callMapsis('get_lojas'),
      callMapsis('get_servicos'),
    ]);
    const loja = normalizeLojas(lojasResult).find(l => l.id === `${id_loja_mapsis}|${cod_loja}`);
    resumo_loja = loja?.title || cod_loja;
    const servico = normalizeServicos(servicosResult).find(s => s.id === String(id_servico_mapsis));
    resumo_servico = servico?.title || '';

    if (boxId) {
      const boxResult = await callMapsis('get_boxes', { cod_loja, id_loja_mapsis });
      const tecnico = normalizeTecnicos(boxResult).find(t => t.id === String(boxId));
      resumo_tecnico = tecnico?.title || 'Técnico selecionado';
    }
  } catch { /* resumo com o que tiver */ }

  return {
    screen: 'CONFIRMACAO',
    data: {
      resumo_loja,
      resumo_servico,
      resumo_data: `${isoToBr(data_agendamento)} às ${hora_agendamento}`,
      resumo_tecnico,
    },
  };
}

// ─── Router ───────────────────────────────────────────────────────────────────

const HANDLERS = {
  IDENTIFICACAO: handleIdentificacao,
  CADASTRO: handleCadastro,
  SELECAO_VEICULO: handleSelecaoVeiculo,
  SERVICO_LOJA: handleServicosLoja,
  DATA_TECNICO: handleDataTecnico,
  SELECAO_HORARIO: handleSelecaoHorario,
  CONTATO: handleContato,
};

export async function handleWhatsAppFlows(req, res) {
  // Log de cada requisição para diagnóstico
  const isEncrypted = !!req.body?.encrypted_flow_data;
  console.log(`[WA Flows] POST recebido | encriptado=${isEncrypted} | keys=${Object.keys(req.body || {}).join(',')}`);

  let decrypted, aesKey, iv;

  try {
    ({ decrypted, aesKey, iv } = decryptRequest(req.body));
  } catch (err) {
    console.error('[WA Flows] Descriptografia falhou:', err.message);
    // Se a requisição parece ser um ping (sem dados de negócio), responde mesmo assim
    // para não bloquear o health check de verificação de endpoint
    if (!isEncrypted || !req.body?.encrypted_aes_key) {
      console.warn('[WA Flows] Respondendo ping sem descriptografia (fallback)');
      return res.json({ data: { status: 'active' } });
    }
    return res.status(421).json({ error: 'Falha na descriptografia' });
  }

  const { action, data = {}, screen } = decrypted;
  console.log(`[WA Flows] action=${action} screen=${screen || '-'}`);

  // Ping de saúde enviado pelo WhatsApp ao registrar o endpoint
  if (action === 'ping') {
    console.log('[WA Flows] Ping recebido → respondendo active');
    return sendFlowResponse(res, { data: { status: 'active' } }, aesKey, iv);
  }

  let result;
  try {
    if (action === 'INIT') {
      result = await handleInit();
    } else if (action === 'data_exchange') {
      const handler = HANDLERS[screen];
      if (!handler) throw new Error(`Tela desconhecida: ${screen}`);
      result = await handler(data);
    } else {
      result = { screen: 'IDENTIFICACAO', data: {} };
    }
  } catch (err) {
    console.error('[WA Flows] Erro ao processar ação:', err.message);
    result = {
      screen: screen || 'IDENTIFICACAO',
      data: { error_messages: { cpf_cnpj: 'Ocorreu um erro. Tente novamente.' } },
    };
  }

  const response = { version: '3.0', screen: result.screen, data: result.data };
  sendFlowResponse(res, response, aesKey, iv);
}
