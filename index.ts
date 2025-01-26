import express, { type Application, type Request, type Response, type NextFunction, type RequestHandler } from 'express'
import jwt, { type JwtPayload } from 'jsonwebtoken'
import bcrypt from 'bcrypt'
import { PrismaClient } from '@prisma/client'
import bodyParser from 'body-parser'
import dotenv from 'dotenv'
import { z } from 'zod'
import rateLimit from "express-rate-limit";

dotenv.config()

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // Máximo 100 solicitudes por IP
  message: { message: "Too many requests. Please try again later." },
});

const app: Application = express()
const prisma = new PrismaClient()
const PORT = process.env.PORT || 3000
const JWT_SECRET = process.env.JWT_SECRET || "default_secret"

app.use(bodyParser.json())
app.use(limiter);

interface AuthenticatedRequest extends Request {
  user?: JwtPayload | string
}

const authenticateToken = (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
) => {
  const token = req.headers.authorization?.split(" ")[1]

  if (!token) return res.status(401).json({ message: "Unauthorized" })

  try {
    const user = jwt.verify(token, JWT_SECRET)
    req.user = user
    next()
  } catch (error) {
    return res.status(403).json({ message: 'Invalid token' })
  }
}

const registerSchema = z.object({
  name: z.string().min(1, "Name is required"),
  email: z.string().email("Invalid email"),
  password: z.string().min(6, "Password must be at least 6 characters")
})

const loginSchema = z.object({
  email: z.string().email("Invalid email"),
  password: z.string().min(6, "Password must be at least 6 characters")
})

const todoSchema = z.object({
  title: z.string().min(1, "Title is required"),
  description: z.string().min(1, "Description is required")
})

// Register
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = registerSchema.parse(req.body)

    const existingUser = await prisma.user.findUnique({ where: { email } })
    if (existingUser) res.status(400).json({ message: 'Email already in use.' });

    const hashedPassword = await bcrypt.hash(password, 10)
    const newUser = await prisma.user.create({
      data: { name, email, password: hashedPassword }
    })

    const token = jwt.sign({ id: newUser.id, name: newUser.name, email: newUser.email, password: newUser.password }, JWT_SECRET, {
      expiresIn: '1h'
    })

    res.status(201).json({ token })
  } catch (error) {
    res.status(400).json({ message: error || 'Invalid request' });
  }
})

// Generate Refresh Token
const generateRefreshToken = async (userId: number) => {
  const refreshToken = jwt.sign({ userId }, JWT_SECRET, { expiresIn: "7d" });
  await prisma.refreshToken.create({
    data: { token: refreshToken, userId },
  });
  return refreshToken;
};

// Refresh Token Endpoint
app.post("/refresh-token", async (req, res) => {
  const { token } = req.body;

if (!token) res.status(401).json({ message: "Refresh token required" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as JwtPayload;
    const storedToken = await prisma.refreshToken.findUnique({
      where: { token },
    });

    if (!storedToken) res.status(403).json({ message: "Invalid refresh token" });

    const accessToken = jwt.sign({ id: decoded.userId }, JWT_SECRET, { expiresIn: "1h" });

    res.status(200).json({ accessToken });
  } catch (error) {
    res.status(403).json({ message: "Invalid refresh token" });
  }
});

// Update /login to include refresh token
app.post("/login", async (req, res) => {
  try {
    const { email, password } = loginSchema.parse(req.body);

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user || !(await bcrypt.compare(password, user.password))) res.status(401).json({ message: "Invalid credentials." });

    const accessToken = jwt.sign({ id: user?.id, email: user?.email }, JWT_SECRET, { expiresIn: "1h" });
    const refreshToken = await generateRefreshToken(Number(user?.id));

    res.status(200).json({ accessToken, refreshToken });
  } catch (error) {
    res.status(400).json({ message: error || "Invalid request" });
  }
});

// ?: Implement Filtering and Sorting for the To-Do List
app.get("/todos", authenticateToken as RequestHandler, async (req, res) => {
  try {
    const validSortFields = ['id', 'title', 'description'];
    const { page = 1, limit = 10, sortBy = "id", order = "asc", search = "" } = req.query;
    const sortField = validSortFields.includes(String(sortBy)) ? String(sortBy) : 'id';
    const userId = ((req as AuthenticatedRequest).user as JwtPayload).id

    const todos = await prisma.todo.findMany({
    where: {
        userId,
        OR: [
        { title: { contains: String(search) } },
        { description: { contains: String(search) } }
        ]
    },
    skip: (Number(page) - 1) * Number(limit),
    take: Number(limit),
    orderBy: { [sortField]: order === 'desc' ? 'desc' : 'asc' }
    })

    const total = await prisma.todo.count({
      where: {
        userId,
        OR: [
          { title: { contains: search as string } },
          { description: { contains: search as string } }
        ]
      }
    })

    res.status(200).json({
      data: todos,
      page: Number(page),
      limit: Number(limit),
    })
} catch (error) {
console.error('Error in /todos:', error);
res.status(500).json({ message: 'Internal server error', error: String(error) });
}
})

// Get a todo
app.get("/todo/:id", authenticateToken as RequestHandler, async (req, res) => {
  try {
    const { id } = req.params
    const userId = ((req as AuthenticatedRequest).user as JwtPayload).id

    const todo = await prisma.todo.findUnique({ where: { id: Number(id) } });

    if (!todo || todo.userId !== userId) res.status(403).json({ message: 'Forbidden' });

    res.status(200).json(todo)
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' });
  }
})

// Create a todo
app.post("/todo", authenticateToken as RequestHandler, async (req, res) => {
  try {
    const { title, description } = todoSchema.parse(req.body)
    const userId = ((req as AuthenticatedRequest).user as JwtPayload).id

    const newTodo = await prisma.todo.create({
      data: { title, description, userId }
    })

    res.status(201).json(newTodo)
  } catch (error) {
    res.status(400).json({ message: error || 'Invalid request' });
  }
})

// Update a todo
app.put("/todo/:id", authenticateToken as RequestHandler, async (req, res) => {
  try {
    const { id } = req.params
    const { title, description } = req.body
    const userId = ((req as AuthenticatedRequest).user as JwtPayload).id

    const todo = await prisma.todo.findUnique({ where: { id: Number(id) } });

    if (!todo || todo.userId !== userId) res.status(403).json({ message: 'Forbidden' });

    const updatedTodo = await prisma.todo.update({
      where: { id: Number(id) },
      data: { title, description }
    })

    res.status(200).json(updatedTodo)
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' });
  }
})

// Delete a todo
app.delete("/todo/:id", authenticateToken as RequestHandler, async (req, res) => {
  try {
    const { id } = req.params
    const userId = ((req as AuthenticatedRequest).user as JwtPayload).id

    const todo = await prisma.todo.findUnique({ where: { id: Number(id) } });

    if (!todo || todo.userId !== userId) res.status(403).json({ message: 'Forbidden' });

    await prisma.todo.delete({ where: { id: Number(id) } })

    res.status(204).json()
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' });
  }
})

app.listen(PORT, () => {
  console.log(`Server is running on port http://localhost:${PORT}`)
})

export default app
