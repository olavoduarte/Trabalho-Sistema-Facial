const mongoose = require('mongoose')

const turmaSchema = new mongoose.Schema({
  nome:{
    type:String,
    required:true
  },

  periodo:{
    type:String,
    required:true
  },

  curso:{
    type:mongoose.Schema.Types.ObjectId,
    ref:'Curso',
    required:true
  },

  professor:{
    type:mongoose.Schema.Types.ObjectId,
    ref:'Professor',
    required:true
  }
}, { timestamps:true })

module.exports = mongoose.model(
  'Turma',
  turmaSchema
)
