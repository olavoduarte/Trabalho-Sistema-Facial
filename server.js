const path = require('path')
const crypto = require('crypto')
const express = require('express')
const mongoose = require('mongoose')
const cors = require('cors')
const bodyParser = require('body-parser')
const { engine } = require('express-handlebars')
require('dotenv').config()

const app = express()

app.use(cors())
app.use(bodyParser.json({ limit: '50mb' }))
app.use(bodyParser.urlencoded({ extended: true }))
app.use(express.static('public'))

app.engine('handlebars', engine({
  defaultLayout: 'main',
  helpers: {
    eq: (a, b) => String(a) === String(b),
    formatDateInput: (value) => value || new Date().toISOString().slice(0, 10)
  }
}))
app.set('view engine', 'handlebars')
app.set('views', path.join(__dirname, 'views'))

const mongoUrl = process.env.MONGO_URL

if (!mongoUrl) {
  console.log('MONGO_URL não encontrada no .env')
  process.exit(1)
}

mongoose.connect(mongoUrl)
mongoose.connection.on('connected', () => {
  console.log('MongoDB Atlas conectado')
})
mongoose.connection.on('error', (err) => {
  console.log('Erro MongoDB:', err)
})

const professorSchema = new mongoose.Schema({
  nome: { type: String, required: true },
  email: { type: String, required: true },
  matricula: { type: String, required: true }
}, { timestamps: true })
professorSchema.index({ matricula: 1 }, { unique: true })
const Professor = mongoose.model('Professor', professorSchema)

const cursoSchema = new mongoose.Schema({
  nome: { type: String, required: true },
  codigo: { type: String, required: true }
}, { timestamps: true })
cursoSchema.index({ codigo: 1 }, { unique: true })
const Curso = mongoose.model('Curso', cursoSchema)

const turmaSchema = new mongoose.Schema({
  nome: { type: String, required: true },
  periodo: { type: String, required: true },
  curso: { type: mongoose.Schema.Types.ObjectId, ref: 'Curso', required: true },
  professor: { type: mongoose.Schema.Types.ObjectId, ref: 'Professor' },
  professores: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Professor' }]
}, { timestamps: true })
const Turma = mongoose.model('Turma', turmaSchema)

const alunoSchema = new mongoose.Schema({
  nome: { type: String, required: true },
  email: { type: String, required: true },
  telefone: { type: String },
  ra: { type: String, required: true },
  curso: { type: mongoose.Schema.Types.ObjectId, ref: 'Curso', required: true },
  turma: { type: mongoose.Schema.Types.ObjectId, ref: 'Turma', required: true },
  facialCadastrada: { type: Boolean, default: false }
}, { timestamps: true })
alunoSchema.index({ ra: 1 }, { unique: true })
const Aluno = mongoose.model('Aluno', alunoSchema)

const usuarioSchema = new mongoose.Schema({
  nome: { type: String, required: true },
  ra: { type: String, required: true },
  aluno: { type: mongoose.Schema.Types.ObjectId, ref: 'Aluno' },
  descriptor: { type: [Number], required: true }
}, { timestamps: true })
usuarioSchema.index({ ra: 1 }, { unique: true })
const Usuario = mongoose.model('Usuario', usuarioSchema)

const presencaSchema = new mongoose.Schema({
  ra: { type: String, required: true },
  aluno: { type: String, required: true },
  alunoId: { type: mongoose.Schema.Types.ObjectId, ref: 'Aluno' },
  turma: { type: mongoose.Schema.Types.ObjectId, ref: 'Turma' },
  data: { type: String, required: true },
  horario: { type: String, required: true },
  origem: { type: String, default: 'facial' }
}, { timestamps: true })
presencaSchema.index(
  { ra: 1, data: 1 },
  {
    unique: true,
    partialFilterExpression: {
      ra: { $type: 'string' }
    }
  }
)
const Presenca = mongoose.model('Presenca', presencaSchema)

const acessoSchema = new mongoose.Schema({
  nome: { type: String, required: true },
  usuario: { type: String, required: true, lowercase: true, trim: true },
  email: { type: String, lowercase: true, trim: true },
  senhaHash: { type: String, required: true },
  perfil: { type: String, enum: ['admin', 'professor', 'aluno'], required: true },
  referencia: { type: mongoose.Schema.Types.ObjectId }
}, { timestamps: true })
acessoSchema.index({ usuario: 1 }, { unique: true })
acessoSchema.index({ email: 1 }, { unique: true, sparse: true })
const Acesso = mongoose.model('Acesso', acessoSchema)

const cookieName = 'faceid_auth'
const sessionSecret = process.env.SESSION_SECRET || 'faceid-escola-dev'
const senhaPadrao = '123'

function hashSenha(senha, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.pbkdf2Sync(String(senha), salt, 100000, 64, 'sha512').toString('hex')
  return `${salt}:${hash}`
}

function senhaConfere(senha, senhaHash) {
  const [salt, hash] = String(senhaHash || '').split(':')
  if (!salt || !hash) return false

  const tentativa = hashSenha(senha, salt).split(':')[1]
  if (hash.length !== tentativa.length) return false

  return crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(tentativa))
}

function assinarSessao(payload) {
  const data = Buffer.from(JSON.stringify(payload)).toString('base64url')
  const assinatura = crypto
    .createHmac('sha256', sessionSecret)
    .update(data)
    .digest('base64url')

  return `${data}.${assinatura}`
}

function lerCookies(req) {
  return String(req.headers.cookie || '')
    .split(';')
    .map((item) => item.trim())
    .filter(Boolean)
    .reduce((cookies, item) => {
      const index = item.indexOf('=')
      cookies[item.slice(0, index)] = decodeURIComponent(item.slice(index + 1))
      return cookies
    }, {})
}

function lerSessao(req) {
  const token = lerCookies(req)[cookieName]
  if (!token) return null

  const [data, assinatura] = token.split('.')
  const assinaturaCorreta = crypto
    .createHmac('sha256', sessionSecret)
    .update(data)
    .digest('base64url')

  if (!assinatura || assinatura !== assinaturaCorreta) return null

  try {
    return JSON.parse(Buffer.from(data, 'base64url').toString('utf8'))
  } catch (erro) {
    return null
  }
}

function gravarSessao(res, acesso) {
  const token = assinarSessao({
    id: String(acesso._id),
    nome: acesso.nome,
    perfil: acesso.perfil,
    referencia: acesso.referencia ? String(acesso.referencia) : ''
  })

  res.setHeader('Set-Cookie', `${cookieName}=${encodeURIComponent(token)}; HttpOnly; Path=/; SameSite=Lax; Max-Age=28800`)
}

function limparSessao(res) {
  res.setHeader('Set-Cookie', `${cookieName}=; HttpOnly; Path=/; SameSite=Lax; Max-Age=0`)
}

function carregarSessao(req, res, next) {
  req.auth = lerSessao(req)
  res.locals.auth = req.auth
  next()
}

function exigirLogin(perfil) {
  return (req, res, next) => {
    if (!req.auth) {
      return res.redirect(`/login/${perfil}`)
    }

    if (req.auth.perfil !== perfil) {
      limparSessao(res)
      return res.redirect(`/login/${perfil}`)
    }

    next()
  }
}

async function existeAdministrador() {
  return Boolean(await Acesso.exists({ perfil: 'admin' }))
}

async function adminInicialPendente() {
  const admins = await Acesso.find({ perfil: 'admin' }).select('nome usuario').lean()

  if (admins.length === 0) return true

  return admins.length === 1 &&
    admins[0].usuario === 'admin' &&
    admins[0].nome === 'Administrador'
}

async function exigirAdminOuPrimeiroCadastro(req, res, next) {
  const primeiroAdmin = await adminInicialPendente()

  if (primeiroAdmin) {
    req.primeiroAdmin = true
    res.locals.primeiroAdmin = true
    return next()
  }

  return exigirLogin('admin')(req, res, next)
}

async function criarAcesso({ nome, usuario, email, senha, perfil, referencia }) {
  const usuarioNormalizado = String(usuario || '').trim().toLowerCase()
  const emailNormalizado = String(email || '').trim().toLowerCase()

  if (!nome || !usuarioNormalizado || !emailNormalizado || !senha) {
    throw new Error('Nome, usuario, email e senha são obrigatórios')
  }

  return Acesso.create({
    nome,
    usuario: usuarioNormalizado,
    email: emailNormalizado,
    senhaHash: hashSenha(senha),
    perfil,
    referencia
  })
}

async function usuarioJaExiste(usuario) {
  return Boolean(await Acesso.exists({ usuario: String(usuario || '').trim().toLowerCase() }))
}

async function emailJaExiste(email) {
  return Boolean(await Acesso.exists({ email: String(email || '').trim().toLowerCase() }))
}

async function emailEmUsoPorOutro(email, referencia) {
  return Boolean(await Acesso.exists({
    email: String(email || '').trim().toLowerCase(),
    referencia: { $ne: referencia }
  }))
}

function idsSelecionados(value) {
  if (!value) return []
  return Array.isArray(value) ? value.filter(Boolean) : [value]
}

function telefoneValido(telefone) {
  const digitos = String(telefone || '').replace(/\D/g, '')
  return !telefone || (digitos.length >= 10 && digitos.length <= 11)
}

async function vincularTurmasAoProfessor(professorId, turmasSelecionadas) {
  await Turma.updateMany(
    {
      $or: [
        { professor: professorId },
        { professores: professorId }
      ]
    },
    {
      $pull: { professores: professorId },
      $unset: { professor: '' }
    }
  )

  const ids = idsSelecionados(turmasSelecionadas)
  if (ids.length > 0) {
    await Turma.updateMany({ _id: { $in: ids } }, { $addToSet: { professores: professorId } })
  }
}

async function garantirAcessoAluno(aluno) {
  const acesso = await Acesso.findOne({
    perfil: 'aluno',
    $or: [
      { referencia: aluno._id },
      { usuario: String(aluno.ra).trim().toLowerCase() },
      { email: String(aluno.email || '').trim().toLowerCase() }
    ]
  })

  if (acesso) {
    acesso.nome = aluno.nome
    acesso.usuario = String(aluno.ra).trim().toLowerCase()
    acesso.email = String(aluno.email || '').trim().toLowerCase()
    acesso.senhaHash = hashSenha(senhaPadrao)
    acesso.referencia = aluno._id
    await acesso.save()
    return acesso
  }

  return criarAcesso({
    nome: aluno.nome,
    usuario: aluno.ra,
    email: aluno.email,
    senha: senhaPadrao,
    perfil: 'aluno',
    referencia: aluno._id
  })
}

async function garantirAcessoProfessor(professor) {
  const emailNormalizado = String(professor.email || '').trim().toLowerCase()
  const acesso = await Acesso.findOne({
    perfil: 'professor',
    $or: [
      { referencia: professor._id },
      { usuario: emailNormalizado },
      { email: emailNormalizado }
    ]
  })

  if (acesso) {
    acesso.nome = professor.nome
    acesso.usuario = emailNormalizado
    acesso.email = emailNormalizado
    acesso.senhaHash = hashSenha(senhaPadrao)
    acesso.referencia = professor._id
    await acesso.save()
    return acesso
  }

  return criarAcesso({
    nome: professor.nome,
    usuario: emailNormalizado,
    email: professor.email,
    senha: senhaPadrao,
    perfil: 'professor',
    referencia: professor._id
  })
}

async function carregarEmailReferencia(acesso) {
  if (!acesso || acesso.email || !acesso.referencia) return acesso

  if (acesso.perfil === 'professor') {
    const professor = await Professor.findById(acesso.referencia).select('email')
    if (professor?.email) {
      acesso.email = professor.email
      await acesso.save()
    }
  }

  if (acesso.perfil === 'aluno') {
    const aluno = await Aluno.findById(acesso.referencia).select('email')
    if (aluno?.email) {
      acesso.email = aluno.email
      await acesso.save()
    }
  }

  return acesso
}

app.use(carregarSessao)

function distanciaEuclidiana(a, b) {
  let soma = 0

  for (let i = 0; i < a.length; i++) {
    soma += Math.pow(a[i] - b[i], 2)
  }

  return Math.sqrt(soma)
}

function dataPtBr(date = new Date()) {
  const dia = String(date.getDate()).padStart(2, '0')
  const mes = String(date.getMonth() + 1).padStart(2, '0')
  const ano = date.getFullYear()

  return `${dia}/${mes}/${ano}`
}

function horaPtBr(date = new Date()) {
  return date.toLocaleTimeString('pt-BR')
}

function normalizarData(value) {
  if (!value) return dataPtBr()
  if (value.includes('/')) {
    const [dia, mes, ano] = value.split('/')
    return `${String(dia).padStart(2, '0')}/${String(mes).padStart(2, '0')}/${ano}`
  }

  const [ano, mes, dia] = value.split('-')
  return `${String(dia).padStart(2, '0')}/${String(mes).padStart(2, '0')}/${ano}`
}

function dataParaInput(value) {
  if (!value) {
    const [dia, mes, ano] = dataPtBr().split('/')
    return `${ano}-${mes}-${dia}`
  }
  if (value.includes('-')) return value

  const [dia, mes, ano] = value.split('/')
  return `${ano}-${String(mes).padStart(2, '0')}-${String(dia).padStart(2, '0')}`
}

function dataParaComparacao(value) {
  return dataParaInput(normalizarData(value))
}

function dataNoIntervalo(value, inicio, fim) {
  const data = dataParaComparacao(value)
  return data >= inicio && data <= fim
}

function iniciaisNome(nome = '') {
  return nome
    .split(' ')
    .filter(Boolean)
    .slice(0, 2)
    .map((parte) => parte[0])
    .join('')
    .toUpperCase()
}

function primeiroNome(nome = '') {
  return nome.split(' ').filter(Boolean)[0] || 'Aluno'
}

function dataDePtBr(value) {
  if (!value) return null

  const [dia, mes, ano] = value.split('/')
  return new Date(Number(ano), Number(mes) - 1, Number(dia))
}

function diaSemanaCurto(value) {
  const data = dataDePtBr(normalizarData(value))
  if (!data || Number.isNaN(data.getTime())) return 'Dia'

  return data.toLocaleDateString('pt-BR', { weekday: 'short' }).replace('.', '')
}

function formatarPresencaAluno(presenca) {
  const origem = presenca.origem === 'professor' ? 'Manual' : 'Facial'
  const data = normalizarData(presenca.data)

  return {
    ...presenca,
    data,
    diaSemana: diaSemanaCurto(data),
    origemLabel: origem,
    origemClasse: origem.toLowerCase()
  }
}

function heatmapSemanal(presencas) {
  const datasPresentes = new Set(presencas.map((presenca) => normalizarData(presenca.data)))
  const hoje = new Date()

  return Array.from({ length: 7 }, (_, index) => {
    const data = new Date(hoje)
    data.setDate(hoje.getDate() - (6 - index))

    const dataFormatada = dataPtBr(data)
    const ativo = datasPresentes.has(dataFormatada)

    return {
      label: data.toLocaleDateString('pt-BR', { weekday: 'short' }).replace('.', ''),
      data: dataFormatada,
      ativo
    }
  })
}

function textoBusca(value = '') {
  return String(value)
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
}

function paginarAlunos(alunos, { buscaAlunos = '', paginaAlunos = 1 } = {}) {
  const busca = String(buscaAlunos || '').trim()
  const termo = textoBusca(busca)
  const alunosFiltrados = termo
    ? alunos.filter((aluno) => {
      const texto = textoBusca([
        aluno.nome,
        aluno.email,
        aluno.telefone,
        aluno.ra,
        aluno.curso?.nome,
        aluno.curso?.codigo,
        aluno.turma?.nome,
        aluno.turma?.periodo
      ].filter(Boolean).join(' '))

      return texto.includes(termo)
    })
    : alunos
  const porPagina = 10
  const total = alunosFiltrados.length
  const totalPaginas = Math.max(Math.ceil(total / porPagina), 1)
  const pagina = Math.min(Math.max(Number(paginaAlunos) || 1, 1), totalPaginas)
  const inicio = (pagina - 1) * porPagina
  const criarUrl = (page) => {
    const params = new URLSearchParams()
    if (busca) params.set('buscaAlunos', busca)
    params.set('paginaAlunos', page)
    return `/admin?${params.toString()}`
  }

  return {
    alunos: alunosFiltrados.slice(inicio, inicio + porPagina),
    paginacao: {
      busca,
      pagina,
      porPagina,
      total,
      totalPaginas,
      inicio: total ? inicio + 1 : 0,
      fim: Math.min(inicio + porPagina, total),
      temAnterior: pagina > 1,
      temProxima: pagina < totalPaginas,
      anteriorUrl: criarUrl(pagina - 1),
      proximaUrl: criarUrl(pagina + 1),
      paginas: Array.from({ length: totalPaginas }, (_, index) => ({
        numero: index + 1,
        ativa: index + 1 === pagina,
        url: criarUrl(index + 1)
      }))
    }
  }
}

function paginarRegistros(registros, {
  pagina = 1,
  porPagina = 10,
  path = '',
  pageParam = 'pagina',
  params = {},
  anchor = ''
} = {}) {
  const total = registros.length
  const totalPaginas = Math.max(Math.ceil(total / porPagina), 1)
  const paginaAtual = Math.min(Math.max(Number(pagina) || 1, 1), totalPaginas)
  const inicio = (paginaAtual - 1) * porPagina
  const criarUrl = (page) => {
    const urlParams = new URLSearchParams()

    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null && value !== '') {
        urlParams.set(key, value)
      }
    })

    urlParams.set(pageParam, page)
    return `${path}?${urlParams.toString()}${anchor}`
  }
  const primeiraPagina = Math.max(1, paginaAtual - 3)
  const ultimaPagina = Math.min(totalPaginas, primeiraPagina + 6)
  const inicioJanela = Math.max(1, ultimaPagina - 6)

  return {
    items: registros.slice(inicio, inicio + porPagina),
    paginacao: {
      pagina: paginaAtual,
      porPagina,
      total,
      totalPaginas,
      inicio: total ? inicio + 1 : 0,
      fim: Math.min(inicio + porPagina, total),
      temAnterior: paginaAtual > 1,
      temProxima: paginaAtual < totalPaginas,
      anteriorUrl: criarUrl(paginaAtual - 1),
      proximaUrl: criarUrl(paginaAtual + 1),
      paginas: Array.from({ length: ultimaPagina - inicioJanela + 1 }, (_, index) => {
        const numero = inicioJanela + index

        return {
          numero,
          ativa: numero === paginaAtual,
          url: criarUrl(numero)
        }
      })
    }
  }
}

async function gerarRa() {
  const ano = new Date().getFullYear()
  const total = await Aluno.countDocuments({
    ra: new RegExp(`^${ano}`)
  })

  return `${ano}${String(total + 1).padStart(5, '0')}`
}

async function gerarMatriculaProfessor() {
  let matricula

  do {
    matricula = `PROF${Math.floor(100000 + Math.random() * 900000)}`
  } while (await Professor.exists({ matricula }))

  return matricula
}

async function dadosAdmin(extra = {}) {
  const [professores, cursos, turmas, alunos] = await Promise.all([
    Professor.find().sort({ nome: 1 }).lean(),
    Curso.find().sort({ nome: 1 }).lean(),
    Turma.find().populate('curso').populate('professor').populate('professores').sort({ nome: 1 }).lean(),
    Aluno.find().populate('curso').populate('turma').sort({ nome: 1 }).lean()
  ])
  const alunosPaginados = paginarAlunos(alunos, extra)

  return {
    professores,
    cursos,
    turmas: turmas.map((turma) => {
      const professoresLista = [
        ...(Array.isArray(turma.professores) ? turma.professores : []),
        ...(turma.professor ? [turma.professor] : [])
      ].filter(Boolean)
      const professoresUnicos = professoresLista.filter((professor, index, lista) =>
        lista.findIndex((item) => String(item._id || item) === String(professor._id || professor)) === index
      )

      return {
        ...turma,
        professoresLista: professoresUnicos
      }
    }),
    alunos: alunosPaginados.alunos,
    alunosPaginacao: alunosPaginados.paginacao,
    ...extra
  }
}

app.get('/portal', (req, res) => {
  res.render('portal', { title: 'Portal' })
})

app.get('/login/:perfil', (req, res) => {
  const perfis = {
    admin: 'Administrador',
    professor: 'Professor',
    aluno: 'Aluno'
  }
  const perfil = req.params.perfil

  if (!perfis[perfil]) {
    return res.redirect('/portal')
  }

  if (perfil === 'admin') {
    adminInicialPendente().then((primeiroAdmin) => {
      if (primeiroAdmin) {
        return res.redirect('/admin')
      }

      res.render('login', {
        title: `Login ${perfis[perfil]}`,
        perfil,
        perfilNome: perfis[perfil],
        erro: req.query.erro
      })
    }).catch((erro) => {
      console.log(erro)
      res.redirect('/portal')
    })
    return
  }

  res.render('login', {
    title: `Login ${perfis[perfil]}`,
    perfil,
    perfilNome: perfis[perfil],
    erro: req.query.erro
  })
})

app.post('/login/:perfil', async (req, res) => {
  const { usuario, email, senha } = req.body
  const perfil = req.params.perfil
  let acesso = null

  if (perfil === 'admin') {
    acesso = await Acesso.findOne({
      usuario: String(usuario || '').trim().toLowerCase(),
      perfil
    })
  }

  if (perfil === 'aluno') {
    const aluno = await Aluno.findOne({ ra: String(usuario || '').trim() })
    acesso = aluno ? await garantirAcessoAluno(aluno) : null
  }

  if (perfil === 'professor') {
    const emailNormalizado = String(email || '').trim().toLowerCase()
    const professor = await Professor.findOne({ email: emailNormalizado })
    acesso = professor ? await garantirAcessoProfessor(professor) : null
  }

  if (!acesso || !senhaConfere(senha, acesso.senhaHash)) {
    return res.redirect(`/login/${perfil}?erro=${encodeURIComponent('Usuário, e-mail ou senha inválidos')}`)
  }

  gravarSessao(res, acesso)
  res.redirect(`/${perfil}`)
})

app.get('/logout', (req, res) => {
  limparSessao(res)
  res.redirect('/portal')
})

app.get('/admin', exigirAdminOuPrimeiroCadastro, async (req, res) => {
  res.render('admin', await dadosAdmin({
    title: 'Portal do Admin',
    mensagem: req.query.mensagem,
    primeiroAdmin: req.primeiroAdmin,
    buscaAlunos: req.query.buscaAlunos,
    paginaAlunos: req.query.paginaAlunos
  }))
})

app.post('/admin/administradores', exigirAdminOuPrimeiroCadastro, async (req, res) => {
  try {
    const { nome, usuario, email, senha } = req.body
    const usuarioNormalizado = String(usuario || '').trim().toLowerCase()
    const emailNormalizado = String(email || '').trim().toLowerCase()
    const podeAtualizarAdminPadrao = req.primeiroAdmin && usuarioNormalizado === 'admin'

    if (await usuarioJaExiste(usuario) && !podeAtualizarAdminPadrao) {
      return res.redirect(`/admin?mensagem=${encodeURIComponent('Este usuário já está cadastrado')}`)
    }

    if (await emailJaExiste(email) && !podeAtualizarAdminPadrao) {
      return res.redirect(`/admin?mensagem=${encodeURIComponent('Este e-mail já está cadastrado')}`)
    }

    const acesso = podeAtualizarAdminPadrao
      ? await Acesso.findOneAndUpdate(
        { perfil: 'admin', usuario: 'admin' },
        { $set: { nome, usuario: 'admin', email: emailNormalizado, senhaHash: hashSenha(senha), perfil: 'admin' } },
        { new: true, upsert: true }
      )
      : await criarAcesso({ nome, usuario, email, senha, perfil: 'admin' })

    if (req.primeiroAdmin) {
      await Acesso.deleteOne({
        perfil: 'admin',
        usuario: 'admin',
        nome: 'Administrador',
        _id: { $ne: acesso._id }
      })
    }

    gravarSessao(res, acesso)

    res.redirect('/admin?mensagem=Administrador cadastrado')
  } catch (erro) {
    console.log(erro)

    const mensagem = erro.code === 11000
      ? 'Este usuário já está cadastrado'
      : 'Não foi possível cadastrar o administrador'

    res.redirect(`/admin?mensagem=${encodeURIComponent(mensagem)}`)
  }
})

app.post('/admin/professores', exigirLogin('admin'), async (req, res) => {
  try {
    const { nome, email, turmas } = req.body
    if (await emailJaExiste(email)) {
      return res.redirect(`/admin?mensagem=${encodeURIComponent('Este e-mail já está cadastrado')}`)
    }

    const matricula = await gerarMatriculaProfessor()
    const professor = await Professor.create({ nome, email, matricula })
    await garantirAcessoProfessor(professor)
    await vincularTurmasAoProfessor(professor._id, turmas)
    res.redirect('/admin?mensagem=Professor cadastrado')
  } catch (erro) {
    console.log(erro)
    res.redirect('/admin?mensagem=Não foi possível cadastrar o professor')
  }
})

app.post('/admin/cursos', exigirLogin('admin'), async (req, res) => {
  try {
    const { nome, codigo } = req.body

    await Curso.create({ nome, codigo })
    res.redirect('/admin?mensagem=Curso cadastrado')
  } catch (erro) {
    console.log(erro)
    res.redirect('/admin?mensagem=Não foi possível cadastrar o curso')
  }
})

app.post('/admin/turmas', exigirLogin('admin'), async (req, res) => {
  try {
    const { nome, periodo, curso } = req.body

    await Turma.create({ nome, periodo, curso })
    res.redirect('/admin?mensagem=Turma cadastrada')
  } catch (erro) {
    console.log(erro)
    res.redirect('/admin?mensagem=Não foi possível cadastrar a turma')
  }
})

app.post('/admin/alunos', exigirLogin('admin'), async (req, res) => {
  try {
    const { nome, email, telefone, curso, turma } = req.body
    if (await emailJaExiste(email)) {
      return res.redirect(`/admin?mensagem=${encodeURIComponent('Este e-mail já está cadastrado')}`)
    }

    if (!telefoneValido(telefone)) {
      return res.redirect(`/admin?mensagem=${encodeURIComponent('Informe um celular valido')}`)
    }

    const turmaSelecionada = await Turma.findById(turma).select('curso')

    if (!turmaSelecionada || String(turmaSelecionada.curso) !== String(curso)) {
      return res.redirect(`/admin?mensagem=${encodeURIComponent('Selecione uma turma do curso escolhido')}`)
    }

    const ra = await gerarRa()
    const aluno = await Aluno.create({ nome, email, telefone, curso, turma, ra })

    await garantirAcessoAluno(aluno)
    res.redirect(`/admin/alunos/${aluno._id}/facial`)
  } catch (erro) {
    console.log(erro)
    res.redirect('/admin?mensagem=Não foi possível cadastrar o aluno')
  }
})

app.get('/admin/alunos/:id/editar', exigirLogin('admin'), async (req, res) => {
  const aluno = await Aluno.findById(req.params.id).lean()

  if (!aluno) {
    return res.redirect('/admin?mensagem=Aluno nao encontrado')
  }

  const [cursos, turmas] = await Promise.all([
    Curso.find().sort({ nome: 1 }).lean(),
    Turma.find().populate('curso').sort({ nome: 1 }).lean()
  ])

  res.render('editar-aluno', {
    title: 'Editar Aluno',
    mensagem: req.query.mensagem,
    aluno,
    cursos: cursos.map((curso) => ({
      ...curso,
      selecionado: String(curso._id) === String(aluno.curso)
    })),
    turmas: turmas.map((turma) => ({
      ...turma,
      selecionada: String(turma._id) === String(aluno.turma)
    }))
  })
})

app.post('/admin/alunos/:id', exigirLogin('admin'), async (req, res) => {
  try {
    const { nome, email, telefone, curso, turma } = req.body
    const aluno = await Aluno.findById(req.params.id)

    if (!aluno) {
      return res.redirect('/admin?mensagem=Aluno nao encontrado')
    }

    if (await emailEmUsoPorOutro(email, aluno._id)) {
      return res.redirect(`/admin/alunos/${aluno._id}/editar?mensagem=${encodeURIComponent('Este e-mail ja esta cadastrado')}`)
    }

    if (!telefoneValido(telefone)) {
      return res.redirect(`/admin/alunos/${aluno._id}/editar?mensagem=${encodeURIComponent('Informe um celular valido')}`)
    }

    const turmaSelecionada = await Turma.findById(turma).select('curso')

    if (!turmaSelecionada || String(turmaSelecionada.curso) !== String(curso)) {
      return res.redirect(`/admin/alunos/${aluno._id}/editar?mensagem=${encodeURIComponent('Selecione uma turma do curso escolhido')}`)
    }

    aluno.nome = nome
    aluno.email = email
    aluno.telefone = telefone
    aluno.curso = curso
    aluno.turma = turma
    await aluno.save()

    await garantirAcessoAluno(aluno)
    await Usuario.updateOne({ ra: aluno.ra }, { $set: { nome: aluno.nome, aluno: aluno._id } })
    await Presenca.updateMany({ ra: aluno.ra }, { $set: { aluno: aluno.nome, alunoId: aluno._id, turma: aluno.turma } })

    res.redirect('/admin?mensagem=Aluno atualizado')
  } catch (erro) {
    console.log(erro)
    res.redirect('/admin?mensagem=Nao foi possivel atualizar o aluno')
  }
})

app.post('/admin/alunos/:id/excluir', exigirLogin('admin'), async (req, res) => {
  try {
    const aluno = await Aluno.findById(req.params.id)

    if (!aluno) {
      return res.redirect('/admin?mensagem=Aluno nao encontrado')
    }

    await Promise.all([
      Acesso.deleteMany({
        perfil: 'aluno',
        $or: [
          { referencia: aluno._id },
          { usuario: String(aluno.ra).trim().toLowerCase() },
          { email: String(aluno.email || '').trim().toLowerCase() }
        ]
      }),
      Usuario.deleteMany({ $or: [{ ra: aluno.ra }, { aluno: aluno._id }] }),
      Presenca.deleteMany({ $or: [{ ra: aluno.ra }, { alunoId: aluno._id }] }),
      Aluno.deleteOne({ _id: aluno._id })
    ])

    res.redirect('/admin?mensagem=Aluno excluido')
  } catch (erro) {
    console.log(erro)
    res.redirect(`/admin/alunos/${req.params.id}/editar?mensagem=${encodeURIComponent('Nao foi possivel excluir o aluno')}`)
  }
})

app.get('/admin/professores/:id/editar', exigirLogin('admin'), async (req, res) => {
  const professor = await Professor.findById(req.params.id).lean()

  if (!professor) {
    return res.redirect('/admin?mensagem=Professor nao encontrado')
  }

  const turmas = await Turma.find().populate('curso').sort({ nome: 1 }).lean()

  res.render('editar-professor', {
    title: 'Editar Professor',
    mensagem: req.query.mensagem,
    professor,
    turmas: turmas.map((turma) => ({
      ...turma,
      selecionada:
        String(turma.professor) === String(professor._id) ||
        (Array.isArray(turma.professores) && turma.professores.some((id) => String(id._id || id) === String(professor._id)))
    }))
  })
})

app.post('/admin/professores/:id', exigirLogin('admin'), async (req, res) => {
  try {
    const { nome, email, turmas } = req.body
    const professor = await Professor.findById(req.params.id)

    if (!professor) {
      return res.redirect('/admin?mensagem=Professor nao encontrado')
    }

    if (await emailEmUsoPorOutro(email, professor._id)) {
      return res.redirect(`/admin/professores/${professor._id}/editar?mensagem=${encodeURIComponent('Este e-mail ja esta cadastrado')}`)
    }

    professor.nome = nome
    professor.email = email
    await professor.save()

    await garantirAcessoProfessor(professor)
    await vincularTurmasAoProfessor(professor._id, turmas)

    res.redirect('/admin?mensagem=Professor atualizado')
  } catch (erro) {
    console.log(erro)
    res.redirect('/admin?mensagem=Nao foi possivel atualizar o professor')
  }
})

app.post('/admin/professores/:id/excluir', exigirLogin('admin'), async (req, res) => {
  try {
    const professor = await Professor.findById(req.params.id)

    if (!professor) {
      return res.redirect('/admin?mensagem=Professor nao encontrado')
    }

    await Promise.all([
      Turma.updateMany(
        {
          $or: [
            { professor: professor._id },
            { professores: professor._id }
          ]
        },
        {
          $pull: { professores: professor._id },
          $unset: { professor: '' }
        }
      ),
      Acesso.deleteMany({
        perfil: 'professor',
        $or: [
          { referencia: professor._id },
          { usuario: String(professor.email || '').trim().toLowerCase() },
          { email: String(professor.email || '').trim().toLowerCase() }
        ]
      }),
      Professor.deleteOne({ _id: professor._id })
    ])

    res.redirect('/admin?mensagem=Professor excluido')
  } catch (erro) {
    console.log(erro)
    res.redirect(`/admin/professores/${req.params.id}/editar?mensagem=${encodeURIComponent('Nao foi possivel excluir o professor')}`)
  }
})

app.get('/admin/alunos/:id/facial', exigirLogin('admin'), async (req, res) => {
  const aluno = await Aluno.findById(req.params.id).populate('curso').populate('turma').lean()

  if (!aluno) {
    return res.redirect('/admin?mensagem=Aluno não encontrado')
  }

  res.render('cadastro-facial', {
    title: 'Cadastro Facial',
    aluno,
    layout: false
  })
})

app.post('/api/alunos/:id/facial', exigirLogin('admin'), async (req, res) => {
  try {
    const { descriptor } = req.body
    const aluno = await Aluno.findById(req.params.id)

    if (!aluno || !descriptor) {
      return res.json({
        success: false,
        mensagem: 'Dados inválidos'
      })
    }

    if (aluno.facialCadastrada && await Usuario.exists({ ra: aluno.ra })) {
      return res.json({
        success: false,
        mensagem: 'Facial ja cadastrada para este aluno'
      })
    }

    const usuarios = await Usuario.find({ ra: { $ne: aluno.ra } }).lean()
    const facialDuplicada = usuarios.some((usuario) =>
      Array.isArray(usuario.descriptor) &&
      usuario.descriptor.length === descriptor.length &&
      distanciaEuclidiana(descriptor, usuario.descriptor) <= 0.55
    )

    if (facialDuplicada) {
      return res.json({
        success: false,
        mensagem: 'Esta facial ja esta cadastrada para outro aluno'
      })
    }

    await Usuario.updateOne(
      { ra: aluno.ra },
      {
        $set: {
          nome: aluno.nome,
          ra: aluno.ra,
          aluno: aluno._id,
          descriptor
        }
      },
      { upsert: true }
    )

    aluno.facialCadastrada = true
    await aluno.save()

    res.json({
      success: true,
      mensagem: 'Facial cadastrada com sucesso'
    })
  } catch (erro) {
    console.log(erro)

    res.status(500).json({
      success: false,
      mensagem: 'Erro ao cadastrar facial'
    })
  }
})

app.get('/professor', exigirLogin('professor'), async (req, res) => {
  const professorId = req.auth.perfil === 'professor' ? req.auth.referencia : req.query.professor
  const professor = professorId ? await Professor.findById(professorId).lean() : null
  const filtro = professorId
    ? {
        $or: [
          { professor: professorId },
          { professores: professorId }
        ]
      }
    : {}
  const turmas = await Turma.find(filtro).populate('curso').populate('professor').populate('professores').sort({ nome: 1 }).lean()

  res.render('professor', {
    title: 'Portal do Professor',
    professor,
    professorId,
    turmas
  })
})

app.get('/professor/turmas/:id', exigirLogin('professor'), async (req, res) => {
  const turma = await Turma.findById(req.params.id).populate('curso').populate('professor').populate('professores').lean()

  if (!turma) {
    return res.redirect('/professor')
  }

  const professorDaTurma =
    (turma.professor && String(turma.professor._id) === String(req.auth.referencia)) ||
    (Array.isArray(turma.professores) && turma.professores.some((professor) => String(professor._id) === String(req.auth.referencia)))

  if (req.auth.perfil === 'professor' && !professorDaTurma) {
    return res.redirect('/professor')
  }

  const dataChamada = req.query.dataChamada || req.query.data || dataParaInput()
  const dataInicio = req.query.dataInicio || req.query.data || dataChamada
  const dataFim = req.query.dataFim || req.query.data || dataInicio
  const buscaAluno = String(req.query.buscaAluno || '').trim()
  const termoBuscaAluno = textoBusca(buscaAluno)
  const dataChamadaNormalizada = normalizarData(dataChamada)
  const dataInicioNormalizada = normalizarData(dataInicio)
  const dataFimNormalizada = normalizarData(dataFim)
  const periodoLabel = dataInicio === dataFim
    ? dataInicioNormalizada
    : `${dataInicioNormalizada} ate ${dataFimNormalizada}`
  const alunos = await Aluno.find({ turma: turma._id }).sort({ nome: 1 }).lean()
  const rasAlunos = alunos.map((aluno) => aluno.ra)
  const presencasCandidatas = await Presenca.find({
    $or: [
      { turma: turma._id },
      { ra: { $in: rasAlunos } }
    ]
  }).lean()
  const presencasDaLista = presencasCandidatas.filter((presenca) => normalizarData(presenca.data) === dataChamadaNormalizada)
  const presencasHistorico = presencasCandidatas.filter((presenca) => dataNoIntervalo(presenca.data, dataInicio, dataFim))
  const presencasPorAluno = new Map()

  for (const presenca of presencasDaLista) {
    const ra = String(presenca.ra)
    const atual = presencasPorAluno.get(ra)

    if (!atual || dataParaComparacao(presenca.data) > dataParaComparacao(atual.data)) {
      presencasPorAluno.set(ra, presenca)
    }
  }

  const listaCompleta = alunos.map((aluno) => {
    const presencaAluno = presencasPorAluno.get(String(aluno.ra))

    return {
      ...aluno,
      presente: Boolean(presencaAluno),
      horario: presencaAluno?.horario || '',
      dataPresenca: presencaAluno ? normalizarData(presencaAluno.data) : '',
      origem: presencaAluno?.origem || '',
      origemLabel: presencaAluno?.origem === 'facial' ? 'Facial' : 'Manual',
      presencaFacial: presencaAluno?.origem === 'facial',
      faltas: null
    }
  })
  const filtrarPorAluno = (item) => {
    if (!termoBuscaAluno) return true

    return textoBusca([
      item.nome,
      item.aluno,
      item.email,
      item.ra,
      item.curso?.nome,
      item.curso?.codigo,
      item.turma?.nome,
      turma.nome,
      turma.curso?.nome,
      turma.curso?.codigo
    ].filter(Boolean).join(' ')).includes(termoBuscaAluno)
  }
  const listaFiltrada = listaCompleta.filter(filtrarPorAluno)

  const historico = presencasHistorico
    .slice()
    .map((presenca) => ({
      ...presenca,
      data: normalizarData(presenca.data),
      origem: presenca.origem === 'professor' ? 'Manual' : 'Facial',
      nome: presenca.aluno
    }))
    .filter(filtrarPorAluno)
    .sort((a, b) => dataParaComparacao(b.data).localeCompare(dataParaComparacao(a.data)))
  const paramsProfessor = {
    dataChamada,
    dataInicio,
    dataFim,
    buscaAluno
  }
  const listaPaginada = paginarRegistros(listaFiltrada, {
    pagina: req.query.paginaLista,
    path: `/professor/turmas/${turma._id}`,
    pageParam: 'paginaLista',
    params: {
      ...paramsProfessor,
      paginaHistorico: req.query.paginaHistorico
    }
  })
  const historicoPaginado = paginarRegistros(historico, {
    pagina: req.query.paginaHistorico,
    path: `/professor/turmas/${turma._id}`,
    pageParam: 'paginaHistorico',
    params: {
      ...paramsProfessor,
      paginaLista: req.query.paginaLista
    }
  })

  res.render('turma-professor', {
    title: 'Turma',
    turma,
    mensagem: req.query.mensagem,
    tipoMensagem: req.query.tipoMensagem || '',
    dataInput: dataChamada,
    hojeInput: dataParaInput(),
    dataChamada,
    dataChamadaLabel: dataChamadaNormalizada,
    dataInicio,
    dataFim,
    data: periodoLabel,
    buscaAluno,
    lista: listaPaginada.items,
    listaPaginacao: listaPaginada.paginacao,
    historico: historicoPaginado.items,
    historicoPaginacao: historicoPaginado.paginacao
  })
})

app.post('/professor/presencas', exigirLogin('professor'), async (req, res) => {
  try {
    const { turmaId, alunoId, data, dataChamada, dataInicio, dataFim, status, buscaAluno } = req.body
    const presente = status === 'presente'
    const voltarParaLista = (mensagem, tipoMensagem = 'success') => {
      const params = new URLSearchParams({
        dataChamada: dataChamada || data,
        dataInicio: dataInicio || data,
        dataFim: dataFim || dataInicio || data
      })

      if (mensagem) params.set('mensagem', mensagem)
      if (mensagem) params.set('tipoMensagem', tipoMensagem)
      if (buscaAluno) params.set('buscaAluno', buscaAluno)

      return res.redirect(`/professor/turmas/${turmaId}?${params.toString()}`)
    }
    const turma = await Turma.findById(turmaId)

    const professorDaTurma = turma && (
      String(turma.professor || '') === String(req.auth.referencia) ||
      (Array.isArray(turma.professores) && turma.professores.some((professorId) => String(professorId) === String(req.auth.referencia)))
    )

    if (!turma || (req.auth.perfil === 'professor' && !professorDaTurma)) {
      return res.redirect('/professor')
    }

    const aluno = await Aluno.findById(alunoId)
    const dataPresenca = normalizarData(data)

    if (!aluno) {
      return voltarParaLista('Aluno nao encontrado', 'error')
    }

    if (!presente && dataParaComparacao(dataPresenca) > dataParaInput()) {
      return voltarParaLista('Nao e possivel lancar falta para uma data futura.', 'error')
    }

    const presencaExistente = await Presenca.findOne({
      ra: aluno.ra,
      data: dataPresenca
    })

    if (presencaExistente?.origem === 'facial') {
      return voltarParaLista('Nao e possivel aplicar falta ou alterar uma presenca registrada por facial.', 'error')
    }

    if (presente) {
      if (presencaExistente) {
        return voltarParaLista('Presenca ja lancada para esta data', 'error')
      }

      const agora = new Date()

      await Presenca.create({
        ra: aluno.ra,
        aluno: aluno.nome,
        alunoId: aluno._id,
        turma: turmaId,
        data: dataPresenca,
        horario: horaPtBr(agora),
        origem: 'professor'
      })
    } else {
      if (!presencaExistente) {
        return voltarParaLista('Aluno ja esta como falta nesta data', 'error')
      }

      await Presenca.deleteOne({
        ra: aluno.ra,
        data: dataPresenca
      })
    }

    return voltarParaLista(presente ? 'Presenca lancada com sucesso.' : 'Falta lancada com sucesso.')
  } catch (erro) {
    console.log(erro)
    res.redirect('/professor')
  }
})

app.get('/aluno', exigirLogin('aluno'), async (req, res) => {
  const alunoId = req.auth.perfil === 'aluno' ? req.auth.referencia : req.query.aluno
  const aluno = alunoId
    ? await Aluno.findById(alunoId).populate('curso').populate('turma').lean()
    : null

  let presencas = []
  let historicoPresencas = []
  let historicoPaginacao = null
  let heatmap = []
  let faltas = 0
  let totalDias = 0
  let frequenciaPercent = 0
  let faltaClasse = 'warning'

  if (aluno) {
    const dataCadastroAluno = aluno.createdAt
      ? dataParaInput(dataPtBr(new Date(aluno.createdAt)))
      : '0000-01-01'
    presencas = (await Presenca.find({ ra: aluno.ra }).sort({ createdAt: -1 }).lean())
      .filter((presenca) => dataParaComparacao(presenca.data) >= dataCadastroAluno)
    const historicoCompleto = presencas
      .map(formatarPresencaAluno)
      .sort((a, b) => dataParaComparacao(b.data).localeCompare(dataParaComparacao(a.data)))
    const historicoPaginado = paginarRegistros(historicoCompleto, {
      pagina: req.query.paginaHistorico,
      path: '/aluno',
      pageParam: 'paginaHistorico'
    })
    historicoPresencas = historicoPaginado.items
    historicoPaginacao = historicoPaginado.paginacao
    heatmap = heatmapSemanal(presencas)
    const presencasNormalizadas = new Set(presencas.map((presenca) => normalizarData(presenca.data)))
    const diasTurma = (await Presenca.distinct('data', { turma: aluno.turma._id }))
      .filter((data) => dataParaComparacao(data) >= dataCadastroAluno)
    totalDias = new Set(diasTurma.map(normalizarData)).size
    faltas = Math.max(totalDias - presencasNormalizadas.size, 0)
    frequenciaPercent = totalDias > 0 ? Math.round((presencasNormalizadas.size / totalDias) * 100) : 0
    faltaClasse = faltas >= 3 ? 'danger' : 'warning'
  }

  res.render('aluno', {
    title: 'Portal do Aluno',
    alunoId,
    aluno,
    presencas,
    historicoPresencas,
    historicoPaginacao,
    heatmap,
    totalDias,
    faltas,
    frequenciaPercent,
    faltaClasse,
    iniciaisAluno: iniciaisNome(aluno?.nome),
    saudacaoNome: primeiroNome(aluno?.nome)
  })
})

app.post('/cadastrar', async (req, res) => {
  try {
    const { nome, ra, descriptor } = req.body

    if (!nome || !ra || !descriptor) {
      return res.json({
        success: false,
        mensagem: 'Dados inválidos'
      })
    }

    const usuariosCadastrados = await Usuario.find({ ra: { $ne: ra } }).lean()
    const facialJaCadastrada = usuariosCadastrados.some((usuario) =>
      Array.isArray(usuario.descriptor) &&
      usuario.descriptor.length === descriptor.length &&
      distanciaEuclidiana(descriptor, usuario.descriptor) <= 0.55
    )

    if (facialJaCadastrada) {
      return res.json({
        success: false,
        mensagem: 'Esta facial ja esta cadastrada'
      })
    }

    await Usuario.updateOne(
      { ra },
      { $setOnInsert: { nome, ra, descriptor } },
      { upsert: true }
    )

    res.json({
      success: true,
      mensagem: 'Usuário cadastrado'
    })
  } catch (erro) {
    console.log(erro)

    if (erro.code === 11000) {
      return res.json({
        success: false,
        mensagem: 'RA já cadastrado'
      })
    }

    res.status(500).json({
      success: false,
      mensagem: 'Erro no servidor'
    })
  }
})

app.post('/presenca', async (req, res) => {
  try {
    const { descriptor } = req.body

    const usuarios = await Usuario.find().populate('aluno')
    let usuarioEncontrado = null
    let menorDistancia = 999

    for (const usuario of usuarios) {
      const distancia = distanciaEuclidiana(descriptor, usuario.descriptor)

      if (distancia < menorDistancia) {
        menorDistancia = distancia
        usuarioEncontrado = usuario
      }
    }

    if (!usuarioEncontrado || menorDistancia > 0.55) {
      return res.json({
        success: false,
        mensagem: 'Rosto não reconhecido'
      })
    }

    const agora = new Date()
    const data = dataPtBr(agora)
    const horario = horaPtBr(agora)
    const aluno = usuarioEncontrado.aluno
    const presencaExistente = await Presenca.findOne({
      ra: usuarioEncontrado.ra,
      data
    }).lean()

    if (presencaExistente) {
      return res.json({
        success: true,
        tipo: 'warning',
        mensagem: 'Presenca ja registrada hoje',
        aluno: usuarioEncontrado.nome
      })
    }

    const resultadoPresenca = await Presenca.updateOne(
      {
        ra: usuarioEncontrado.ra,
        data
      },
      {
        $set: {
          aluno: aluno?.nome || usuarioEncontrado.nome,
          alunoId: aluno?._id,
          turma: aluno?.turma,
          horario
        },
        $setOnInsert: {
          ra: usuarioEncontrado.ra,
          data,
          origem: 'facial'
        }
      },
      { upsert: true }
    )

    if (resultadoPresenca.upsertedCount === 0) {
      return res.json({
        success: true,
        tipo: 'warning',
        mensagem: 'Presença já registrada',
        aluno: usuarioEncontrado.nome
      })
    }

    res.json({
      success: true,
      tipo: 'success',
      mensagem: 'Presença confirmada',
      aluno: usuarioEncontrado.nome
    })
  } catch (erro) {
    console.log(erro)

    if (erro.code === 11000) {
      return res.json({
        success: true,
        tipo: 'warning',
        mensagem: 'Presença já registrada'
      })
    }

    res.status(500).json({
      success: false,
      mensagem: 'Erro no servidor'
    })
  }
})

app.get('/presencas', async (req, res) => {
  try {
    const presencas = await Presenca.find().populate('alunoId').populate('turma').lean()

    res.json(presencas)
  } catch (erro) {
    console.log(erro)

    res.status(500).json({
      success: false
    })
  }
})

app.listen(3000, () => {
  console.log('Servidor rodando')
  console.log('http://localhost:3000')
})
