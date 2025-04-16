import { Router, type Request, type Response } from 'express';
import { User } from '../models/user';
import bcrypt from 'bcrypt';
import jwt  from 'jsonwebtoken';



const SignUp = async (req: Request, res: Response) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      res.status(400).json({ message: 'missing username or password' });
      return;
    }
    const ecxistingUser = await User.findOne({ username });
    if (ecxistingUser) {
      res.status(400).json({ message: 'username taken' });
      return;
    }

    const user = new User({ username, password }); // skapar användaren
    await user.save(); // sparar användaren i databasen

    res.status(201).json({ message: 'successfully signed up user' });
  } catch (error) {
    console.log(error);
    res.status(500).send();
  }
};

const LogIn = async (req: Request, res: Response) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      res.status(400).json({ message: 'missing username or password' });
      return;
    }

    const user = await User.findOne({ username }, '+password');
    if (!user || !(await bcrypt.compare(password, user.password))) {
      res.status(400).json({ message: 'wrong username or password' });
      return;
    }

    const accessToken = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET!,
      {
        expiresIn: '1h',
      }
    );

    res.status(200).json({ accessToken, userId: user._id})
  } catch (error) {
    console.log(error);
    res.status(500).send();
  }
};



export const authRouter = Router();

authRouter.post('/auth/sign-up', SignUp);
authRouter.post('/auth/log-in', LogIn);
