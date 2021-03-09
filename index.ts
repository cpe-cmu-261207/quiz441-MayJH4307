import express from 'express'
import bodyParser from 'body-parser'
import cors from 'cors'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import { body, query, validationResult } from 'express-validator'
import fs from 'fs'
import { userInfo } from 'node:os'

const SECRET_KEY = process.env.SECRET_KEY as string
const app = express()
app.use(bodyParser.json())
app.use(cors())

const PORT = process.env.PORT || 3000
const SECRET = "SIMPLE_SECRET"

interface JWTPayload {
  username: string;
  password: string;
}

interface DbSchema {
  users: User[]
}

const readDbFile = (): DbSchema => {
  const raw = fs.readFileSync('db.json', 'utf8')
  const db: DbSchema = JSON.parse(raw)
  return db
}

interface User {
  username: string
  password: string
  firstname: string 
  lastname: string 
  balance: number
}

type LoginArgs = Pick<User, 'username' | 'password'>

app.post<any,any,LoginArgs>('/login',
  (req, res) => {

    const { username, password } = req.body
    // Use username and password to create token.
    const raw = fs.readFileSync('db.json', 'utf8')
    const db: DbSchema = JSON.parse(raw)
    const user = db.users.find(user => user.username === username)

    if (!user) {
      res.status(400)
      res.json({ message: 'Invalid username or password' })
      return
    }
    if (!bcrypt.compareSync(password, user.password)) {
      res.status(400)
      res.json({ message: 'Invalid username or password' })
      return
    }

    const token = jwt.sign(
      {username: user.username ,password: user.password} as JWTPayload, 
      SECRET_KEY
    )
    return res.status(200).json({
      message: 'Login succesfully',
      token: 'token'
    })
  })

type RegisterArgs = Omit<User, 'balance'>

app.post<any,any,any,any,RegisterArgs>('/register',
  (req, res) => {
    /*const errors = validationResult(req)
    if (!errors.isEmpty()) {
      res.status(400)
      res.json(errors)
      return
    }*/
    const { username, password, firstname, lastname, balance } = req.body
    const db = readDbFile()
    const hashPassword = bcrypt.hashSync(password, 10)
    const user = db.users.find(user => user.username === username)
    if(user){
        res.status(400)
        res.json({message : "Username is already in used"})
        return 
    }
    db.users.push({
      ...body,
      username,
      password: hashPassword,
      firstname,
      lastname,
      balance,
    })
    fs.writeFileSync('db.json', JSON.stringify(db))
    res.json({ message: 'Register complete' })
  })

app.get('/balance',
  (req, res) => {
    const token = req.query.token as string
    if(!token){
      res.status(401)
      res.json({message : "Invalid token"})
      return 
  }
    try {
      const { username } = jwt.verify(token, SECRET) as JWTPayload  
      const db = readDbFile()
      const user = db.users.find(user => user.username === username)
      if (user) {
        res.status(200)
        res.json({ 
          name: user.firstname +" "+user.lastname,
          balance: user.balance,
      })
      return
      }
    }
    catch (e) {
      //response in case of invalid token
      res.status(401)
      res.json({message : e.message})
    }
  })

app.post('/deposit',
  body('amount').isInt({ min: 1 }),
  (req, res) => {
    
    const token = req.headers.authorization as string
    const { username } = jwt.verify(token, SECRET) as JWTPayload
    const amount = Number(req.body)
    const db = readDbFile()
    const user = db.users.find(user => user.username === username)
    const balanceOf = Number(user?.balance)
    let BalUpdate = amount+balanceOf

    if(token){
      res.status(200).json({
        message: "Deposit successfully",
        balance: BalUpdate
      })
      
    }else if (!token) {
      res.status(401)
      res.json({ message: "Invalid token"})
      return
    }else
    //Is amount <= 0 ?
    if (!validationResult(req).isEmpty())
      return res.status(400).json({ message: "Invalid data" })
    
  })

app.post('/withdraw',
  (req, res) => {
    const token = req.headers.authorization as string
    const { username } = jwt.verify(token, SECRET) as JWTPayload
    const withDraw = Number(req.body)
    const db = readDbFile()
    const user = db.users.find(user => user.username === username)
    const balanceOf = Number(user?.balance)
    let BalUpdate = withDraw+balanceOf

    if(token){
      res.status(200).json({
        message: "Withdraw successfully",
        balance: BalUpdate
      })
      
    }else if (!token) {
      res.status(401)
      res.json({ message: "Invalid token"})
      return
    }else
    //Is amount <= 0 ?
    if (!validationResult(req).isEmpty())
      return res.status(400).json({ message: "Invalid data" })
  })

app.delete('/reset', (req, res) => {

  //code your database reset here
  
  return res.status(200).json({
    message: 'Reset database successfully'
  })
})

app.get('/me', (req, res) => {
  res.json({
    firstname: 'Sunisa',
    lastname: 'Deeratram',
    code: '620610818',
    gpa: '3.6x',
  })
})

app.get('/demo', (req, res) => {
  return res.status(200).json({
    message: 'This message is returned from demo route.'
  })
})

app.listen(PORT, () => console.log(`Server is running at ${PORT}`))