import crypto from 'crypto';
import fetch from 'node-fetch';

// ─── MapSis API ───────────────────────────────────────────────────────────────

async function callMapsis(method, params = {}) {
  const { MAPSIS_URL, MAPSIS_USER, MAPSIS_PASS, MAPSIS_KEY } = process.env;

  const url = new URL(`${MAPSIS_URL.replace(/\/$/, '')}/${method}.asp`);
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
    .filter(t => (t.nome_produtivo || t.nome || '').trim().length > 0)
    .map(t => ({
      id: String(t.id_box_mapsis || t.id_consultor_mapsis),
      title: (t.nome_produtivo || t.nome || '').trim(),
    }));
  return [{ id: '0', title: 'Sem preferência' }, ...lista];
}

function normalizeHorarios(result) {
  const raw = result?.horarios || result?.Horarios || [];
  const seen = new Set();
  return (Array.isArray(raw) ? raw : [raw])
    .map(h => (typeof h === 'string' ? h : h?.horario || h?.hora || '').substring(0, 5))
    .filter(t => t && /^\d{2}:\d{2}$/.test(t) && t.endsWith(':00') && !seen.has(t) && seen.add(t))
    .map(t => ({ id: t, title: t }));
}

// Extrai os slots da agenda como pares { box, hora } (grade de box).
// Na grade de consultor o MapSis devolve só strings "HH:mm" (sem box) → box vazio.
function extrairSlots(result) {
  const raw = result?.horarios || result?.Horarios || [];
  return (Array.isArray(raw) ? raw : [raw])
    .map(s => (typeof s === 'string'
      ? { box: '', hora: s.substring(0, 5) }
      : { box: String(s?.box ?? s?.id_box_mapsis ?? ''), hora: String(s?.horario ?? s?.hora ?? '').substring(0, 5) }))
    .filter(s => /^\d{2}:\d{2}$/.test(s.hora));
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

// "2024-06-08" → "08/06/2024"  (fallback: retorna o original se não for YYYY-MM-DD)
function isoToBr(iso = '') {
  const s = String(iso || '').trim();
  const parts = s.split('-');
  if (parts.length !== 3 || !parts[0] || !parts[1] || !parts[2]) return s;
  const [y, m, d] = parts;
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

    const nome = (cliente?.nome_cliente || cliente?.nome || 'Cliente').trim();
    return {
      screen: 'SELECAO_VEICULO',
      data: {
        saudacao: `Ola, ${nome}! Selecione o veiculo para agendar o servico.`,
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
      msg_agenda: '',
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

  // Consulta a grade de TODOS os boxes (sem fixar id_box_mapsis): o MapSis devolve
  // cada horário livre marcado com seu box. Assim mostramos toda a disponibilidade
  // da data e, ao agendar, escolhemos um box que realmente tenha o horário.
  let horariosResult = {};
  try {
    horariosResult = await callMapsis('get_agenda_horario_disponivel', {
      id_veiculo_mapsis,
      id_loja_mapsis,
      id_servico_mapsis,
      data_agendamento: apiDate,
      retorno_consultor: '0',
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
        msg_agenda: `Sem horarios disponiveis em ${apiDate}. Escolha outra data.`,
        error_messages: {
          data_agendamento: 'Sem horarios nesta data. Escolha outra.',
        },
      },
    };
  }

  const dataBr = isoToBr(data_agendamento);
  return {
    screen: 'SELECAO_HORARIO',
    data: {
      cpf_cnpj, id_cliente_mapsis, id_veiculo_mapsis,
      id_servico_mapsis, id_loja_mapsis, cod_loja,
      id_box_mapsis: id_box_mapsis || '0',
      data_agendamento,
      titulo_horario: `Horarios disponiveis para ${dataBr}:`,
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

  // Buscar contatos do cliente para exibir como dica na tela CONTATO.
  // Os hints são pré-formatados no servidor porque WhatsApp Flows só avalia
  // expressões quando o valor inteiro é "${data.campo}" — strings mistas não funcionam.
  let email_hint = 'Ex: nome@email.com', celular_hint = 'Ex: 11999999999';
  try {
    const clienteResult = await callMapsis('get_cliente', { cpf_cnpj });
    const { cliente } = extractCliente(clienteResult);
    if (cliente) {
      const email = (cliente.email || '').trim();
      if (email) email_hint = `Atual: ${email}`;

      const dddCel = String(cliente.ddd_celular || '').trim();
      const cel    = String(cliente.celular     || '').trim();
      const celular = dddCel && cel ? `${dddCel}${cel}` : cel;
      if (celular) celular_hint = `Atual: ${celular}`;
    }
  } catch (e) {
    console.warn('[handleSelecaoHorario] não foi possível buscar contatos:', e.message);
  }

  return {
    screen: 'CONTATO',
    data: {
      cpf_cnpj, id_cliente_mapsis, id_veiculo_mapsis,
      id_servico_mapsis, id_loja_mapsis, cod_loja,
      id_box_mapsis: id_box_mapsis || '0',
      data_agendamento,
      hora_agendamento,
      observacao: observacao || '',
      email_hint,
      celular_hint,
    },
  };
}

// Monta a etiqueta legível do condutor
function condutorLabelDe(condutor, nome_condutor) {
  return condutor === 'outros' && nome_condutor
    ? `Outros – ${nome_condutor}`
    : 'Proprietário';
}

// Busca cliente + veículo + nomes de loja/serviço/técnico e resolve o contato
// (usa o que o cliente digitou; se vazio, mantém o cadastrado). Reutilizado pela
// tela de revisão e pela gravação final.
async function coletarDados(data) {
  const {
    cpf_cnpj, id_veiculo_mapsis, id_servico_mapsis, id_loja_mapsis, cod_loja,
    id_box_mapsis, email, celular, telefone,
  } = data;

  let nome_cliente = '', marca_veiculo = 'Chevrolet', modelo_veiculo = '',
    ano_fabricacao = '', ano_modelo = '', km_atual = '', placa = '', chassi = '';
  let emailAtual = '', celularAtual = '', telefoneAtual = '';

  try {
    const clienteResult = await callMapsis('get_cliente', { cpf_cnpj });
    const { cliente } = extractCliente(clienteResult);
    if (cliente) {
      nome_cliente = cliente.nome_cliente || cliente.nome || '';
      emailAtual = String(cliente.email || '').trim();
      const dddCel = String(cliente.ddd_celular || '').trim();
      const celNum = String(cliente.celular || '').trim();
      celularAtual = dddCel && celNum ? `${dddCel}${celNum}` : celNum;
      const ddd = String(cliente.ddd || '').trim();
      const telNum = String(cliente.telefone || '').trim();
      telefoneAtual = ddd && telNum ? `${ddd}${telNum}` : telNum;

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
  } catch { /* prossegue sem dados completos */ }

  // Contato efetivo: o que foi digitado tem prioridade; senão mantém o cadastrado
  const emailFinal = String(email || '').trim() || emailAtual;
  const celularFinal = String(celular || '').trim() || celularAtual;
  const telefoneFinal = String(telefone || '').trim() || telefoneAtual;

  // Nomes legíveis de loja / serviço / técnico
  let lojaNome = cod_loja, servicoNome = '(nao informado)', tecnicoNome = 'Sem preferencia';
  const boxId = id_box_mapsis && id_box_mapsis !== '0' ? id_box_mapsis : '';
  try {
    const [lojasResult, servicosResult] = await Promise.all([
      callMapsis('get_lojas'),
      callMapsis('get_servicos'),
    ]);
    lojaNome = normalizeLojas(lojasResult).find(l => l.id === `${id_loja_mapsis}|${cod_loja}`)?.title || cod_loja;
    servicoNome = normalizeServicos(servicosResult).find(s => s.id === String(id_servico_mapsis))?.title || '(nao informado)';
    if (boxId) {
      const boxResult = await callMapsis('get_boxes', { cod_loja, id_loja_mapsis });
      tecnicoNome = normalizeTecnicos(boxResult).find(t => t.id === String(boxId))?.title || 'Selecionado';
    }
  } catch { /* usa o que tiver */ }

  return {
    nome_cliente, marca_veiculo, modelo_veiculo, ano_fabricacao, ano_modelo,
    km_atual, placa, chassi,
    emailFinal, celularFinal, telefoneFinal,
    lojaNome, servicoNome, tecnicoNome, boxId,
  };
}

// Monta as strings de resumo (cada uma já inclui o rótulo, pois o WhatsApp Flows
// não interpola expressões embutidas em texto — o valor inteiro deve ser a expressão).
function montarResumos(data, info, condutorLabel) {
  const veiculoLabel = info.modelo_veiculo
    ? `${info.modelo_veiculo.trim()}${info.placa ? ' - ' + info.placa : ''}`
    : (info.placa || 'Veiculo nao informado');

  const contato = [info.emailFinal, info.celularFinal, info.telefoneFinal].filter(Boolean).join(' | ');
  const obs = String(data.observacao || '').trim();

  return {
    resumo_veiculo:  `Veiculo: ${veiculoLabel}`,
    resumo_servico:  `Servico: ${info.servicoNome}`,
    resumo_loja:     `Concessionaria: ${info.lojaNome}`,
    resumo_data:     `Data e hora: ${isoToBr(data.data_agendamento)} as ${data.hora_agendamento}`,
    resumo_tecnico:  `Tecnico/Mecanico: ${info.tecnicoNome}`,
    resumo_condutor: `Condutor: ${condutorLabel}`,
    resumo_contato:  `Contato: ${contato || '(nao informado)'}`,
    resumo_obs:      `Observacoes: ${obs || '(nenhuma)'}`,
  };
}

// Campos crus repassados adiante para que a tela de revisão possa gravar depois
function forwardAgendamento(data, info, condutor, nome_condutor) {
  return {
    cpf_cnpj: data.cpf_cnpj,
    id_cliente_mapsis: data.id_cliente_mapsis || '',
    id_veiculo_mapsis: data.id_veiculo_mapsis,
    id_servico_mapsis: data.id_servico_mapsis,
    id_loja_mapsis: data.id_loja_mapsis,
    cod_loja: data.cod_loja,
    id_box_mapsis: data.id_box_mapsis || '0',
    data_agendamento: data.data_agendamento,
    hora_agendamento: data.hora_agendamento,
    observacao: data.observacao || '',
    condutor: condutor || 'proprietario',
    nome_condutor: nome_condutor || '',
    // contato já resolvido (digitado ou o cadastrado)
    email: info.emailFinal,
    celular: info.celularFinal,
    telefone: info.telefoneFinal,
  };
}

// CONTATO → monta a tela de REVISÃO com tudo preenchido (ainda NÃO grava)
async function handleContato(data) {
  const { condutor, nome_condutor } = data;
  const condutorLabel = condutorLabelDe(condutor, nome_condutor);

  const info = await coletarDados(data);
  const resumos = montarResumos(data, info, condutorLabel);

  return {
    screen: 'REVISAO',
    data: {
      ...resumos,
      msg_erro: '',
      ...forwardAgendamento(data, info, condutor, nome_condutor),
    },
  };
}

// REVISAO → grava o agendamento e finaliza (CONFIRMACAO)
async function handleRevisao(data) {
  const {
    cpf_cnpj, id_veiculo_mapsis, id_servico_mapsis,
    id_loja_mapsis, cod_loja,
    data_agendamento, hora_agendamento, observacao,
    email, celular, telefone,
    condutor, nome_condutor,
  } = data;

  const condutorLabel = condutorLabelDe(condutor, nome_condutor);

  // Anexa o condutor na observação enviada ao MapSis (campo livre)
  const obsPartes = [observacao || ''];
  if (condutor === 'outros' && nome_condutor) obsPartes.push(`Condutor: ${nome_condutor}`);
  const observacaoFinal = obsPartes.filter(Boolean).join(' | ');

  const info = await coletarDados(data);
  const resumos = montarResumos(data, info, condutorLabel);

  const cel = parsePhone(celular);
  const tel = parsePhone(telefone || '');
  const apiDate = isoToBr(data_agendamento);
  const boxId = info.boxId;

  // Campos comuns a qualquer tentativa de agendamento (sem o box)
  const basePayload = {
    cpf_cnpj,
    nome: info.nome_cliente,
    email,
    ddd: tel.ddd,
    telefone: tel.numero,
    ddd_celular: cel.ddd,
    celular: cel.numero,
    cod_loja,
    id_loja_mapsis,
    id_servico_mapsis,
    id_veiculo_mapsis,
    marca_veiculo: info.marca_veiculo,
    modelo_veiculo: info.modelo_veiculo,
    ano_fabricacao: info.ano_fabricacao,
    ano_modelo: info.ano_modelo,
    km_atual: info.km_atual,
    placa: info.placa,
    chassi: info.chassi,
    data_agendamento: apiDate,
    hora_agendamento,
    status_agendamento: 'P',
    // Mídia/origem/aplicação do canal WhatsApp (valores cadastrados no MapSis)
    CalledFrom: 'WHATSAPP',
    origem: 'BLIP - RECEPTIVO',
    origem_lead: 'BLIP - RECEPTIVO',
    como_chegou: 'BLIP - RECEPTIVO',
  };

  // Faz uma tentativa de set_agendamento e devolve o erro do MapSis (ou null)
  const tentarAgendar = async (extra, obs) => {
    try {
      const r = await callMapsis('set_agendamento', { ...basePayload, ...extra, observacao: obs });
      return getErroApi(r);
    } catch (e) {
      console.error('[handleRevisao] set_agendamento exceção:', e.message);
      return 'Falha de comunicacao com o sistema.';
    }
  };

  // Re-consulta a agenda (todos os boxes) no momento da gravação para descobrir
  // quais boxes têm o horário escolhido REALMENTE livre. Isso elimina o
  // "agenda mostrou vaga mas o set_agendamento recusou": só agendamos num box
  // que a própria agenda acabou de confirmar como disponível.
  let agendaResult = {};
  try {
    agendaResult = await callMapsis('get_agenda_horario_disponivel', {
      id_veiculo_mapsis, id_loja_mapsis, id_servico_mapsis,
      data_agendamento: apiDate, retorno_consultor: '0',
    });
  } catch { /* sem agenda */ }

  // Boxes que têm o horário escolhido livre — com o box preferido na frente
  const boxesComHora = [...new Set(
    extrairSlots(agendaResult).filter(s => s.hora === hora_agendamento).map(s => s.box)
  )];
  const ordemBoxes = boxId && boxesComHora.includes(String(boxId))
    ? [String(boxId), ...boxesComHora.filter(b => b !== String(boxId))]
    : boxesComHora;

  let erroSave = null;
  if (ordemBoxes.length && ordemBoxes.some(Boolean)) {
    // Tenta cada box (preferido primeiro) até um aceitar
    erroSave = 'Horario indisponivel.';
    for (const bx of ordemBoxes.filter(Boolean)) {
      const obs = (boxId && bx !== String(boxId))
        ? [observacaoFinal, `Mecanico preferido: ${info.tecnicoNome}`].filter(Boolean).join(' | ')
        : observacaoFinal;
      erroSave = await tentarAgendar({ id_box: bx }, obs);
      if (!erroSave) break;
      console.warn(`[handleRevisao] box ${bx} recusou (${erroSave}). Tentando proximo box...`);
    }
  } else {
    // Grade de consultor (sem box) ou agenda indisponível → deixa o MapSis alocar
    erroSave = await tentarAgendar({}, observacaoFinal);
  }

  // O MapSis devolve HTTP 200 mesmo em falha — o erro vem em retorno.erro
  // (igual getErroApi do PWA). Só mostramos erro se nem o fallback funcionou.
  if (erroSave) {
    console.warn('[handleRevisao] set_agendamento falhou definitivamente:', erroSave);
    return {
      screen: 'REVISAO',
      data: {
        ...resumos,
        msg_erro: `Nao foi possivel agendar: ${erroSave}`,
        ...forwardAgendamento(data, info, condutor, nome_condutor),
      },
    };
  }

  return {
    screen: 'CONFIRMACAO',
    data: {
      resumo_loja: resumos.resumo_loja,
      resumo_servico: resumos.resumo_servico,
      resumo_data: resumos.resumo_data,
      resumo_tecnico: resumos.resumo_tecnico,
      resumo_veiculo: resumos.resumo_veiculo,
      resumo_condutor: resumos.resumo_condutor,
      resumo_contato: resumos.resumo_contato,
      resumo_obs: resumos.resumo_obs,
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
  REVISAO: handleRevisao,
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
