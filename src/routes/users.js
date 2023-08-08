import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import {UserModel} from '../models/Users.js';

const router = express.Router();

router.post("/register", async (req,res) =>{
    const {username,password} = req.body;    
    const user = await UserModel.findOne({username});

    if(user){
        return res.json({message: 'User already exists, Try logging in.'});
    }

    const hashedPass = await bcrypt.hash(password, 10);
    const newUser = new UserModel({username, password:hashedPass});
    await newUser.save();
    res.json({message: 'user registered'});
});

router.post('/login', async (req,res)=>{
    const {username, password} = req.body;
    const user = await UserModel.findOne({username});

    if(!user){
        return res.json({message: "User Doesn't exist, Register First.."});
    }

    const isPassValid = await bcrypt.compare(password, user.password);

    if(!isPassValid)
        return res.json({message:'Username or Password is incorrect'});

    const token = jwt.sign({id: user._id}, "secret");
    res.json({token, userID: user._id});

});
export {router as userRouter};

export const verifyToken = (req,res,next)=>{
    const token = req.headers.Authorization;
    if(token){
        jwt.verify(token, 'secret', (err)=>{
            if(err) return res.sendStatus(403);
            next();
        });
    } else{
        res.sendStatus(401);
    }
} ;