const mongoose = require('mongoose')

const alunoSchema = new mongoose.Schema({
  nome:{
    type:String,
    required:true
  },

  email:{
    type:String,
    required:true
  },

  telefone:{
    type:String
  },

  ra:{
    type:String,
    required:true
  },

  curso:{
    type:mongoose.Schema.Types.ObjectId,
    ref:'Curso',
    required:true
  },

  turma:{
    type:mongoose.Schema.Types.ObjectId,
    ref:'Turma',
    required:true
  },

  facialCadastrada:{
    type:Boolean,
    default:false
  }
}, { timestamps:true })

alunoSchema.index({ ra:1 }, { unique:true })

module.exports = mongoose.model(
  'Aluno',
  alunoSchema
)
