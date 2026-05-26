const mongoose = require('mongoose')

const usuarioSchema = new mongoose.Schema({

  nome:{
    type:String,
    required:true
  },

  ra:{
    type:String,
    required:true
  },

  descriptor:{
    type:[Number],
    required:true
  },

  aluno:{
    type:mongoose.Schema.Types.ObjectId,
    ref:'Aluno'
  }

}, { timestamps:true })

usuarioSchema.index({ ra: 1 }, { unique: true })

module.exports = mongoose.model(
  'Usuario',
  usuarioSchema
)
