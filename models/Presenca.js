const mongoose = require('mongoose')

const presencaSchema = new mongoose.Schema({

  ra:{
    type:String,
    required:true
  },

  aluno:{
    type:String,
    required:true
  },

  alunoId:{
    type:mongoose.Schema.Types.ObjectId,
    ref:'Aluno'
  },

  turma:{
    type:mongoose.Schema.Types.ObjectId,
    ref:'Turma'
  },

  horario:{
    type:String,
    required:true
  },

  data:{
    type:String,
    required:true
  },

  origem:{
    type:String,
    default:'facial'
  }

}, { timestamps:true })

presencaSchema.index(
  { ra: 1, data: 1 },
  {
    unique: true,
    partialFilterExpression: {
      ra: { $type: 'string' }
    }
  }
)

module.exports = mongoose.model(
  'Presenca',
  presencaSchema
)
