import express from 'express';
import cors from 'cors'; 
import mongoose from 'mongoose'; 
import {userRouter} from './routes/users.js';
import {recipesRouter} from './routes/recipes.js';

const app = express();

app.use(express.json());
app.use(cors());
app.use("/auth",userRouter);
app.use("/recipes",recipesRouter);

mongoose.connect('mongodb://127.0.0.1:27017/recipe').then(()=>{
    console.log('connected to DB');
});

app.listen(3001, ()=>{
    console.log('server started at port: 3001');
})
