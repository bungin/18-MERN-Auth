const typeDefs = `
  type Book {
    _id: ID!
    title: String
    author: String
    }
    
    type Query {
      books: [Book]
    }
      
    type Mutation {
      saveBook(title: String!, author: String!): Book
    }
    `