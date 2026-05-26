const mongoose = require('mongoose')

const professorSchema = new mongoose.Schema({
  nome:{
    type:String,
    required:true
  },

  email:{
    type:String,
    required:true
  },

  matricula:{
    type:String,
    required:true
  }
}, { timestamps:true })

professorSchema.index({ matricula:1 }, { unique:true })

module.exports = mongoose.model(
  'Professor',
  professorSchema
)
