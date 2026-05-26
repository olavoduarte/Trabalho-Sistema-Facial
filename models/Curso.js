const mongoose = require('mongoose')

const cursoSchema = new mongoose.Schema({
  nome:{
    type:String,
    required:true
  },

  codigo:{
    type:String,
    required:true
  }
}, { timestamps:true })

cursoSchema.index({ codigo:1 }, { unique:true })

module.exports = mongoose.model(
  'Curso',
  cursoSchema
)
