import express from 'express';
import mongoose from "mongoose";

import * as UserController from './controllers/UserController.js'
import * as PostController from './controllers/PostController.js'

import {registerValidation, loginValidation, postCreateValidation} from "./validations.js";

import checkAuth from "./utils/checkAuth.js";

mongoose
    .connect('mongodb+srv://user:user@cluster0.pqndw.mongodb.net/blog?retryWrites=true&w=majority')
    .then(() => console.log('DB ok'))
    .catch((err) => console.log('DB error', err));

const app = express();

app.use(express.json());

app.get('/', (req, res) => {
    res.send('Hello');
})

app.post('/auth/login', loginValidation, UserController.login);
app.post('/auth/register', registerValidation, UserController.register);
app.get('/auth/me', checkAuth, UserController.getMe);

app.get('/posts', PostController.getAll);
app.get('/posts:id', PostController.getOne);
app.post('/posts', checkAuth, postCreateValidation, PostController.create);
// app.delete('/posts', PostController.remove);
// app.path('/posts', PostController.update);

app.listen(4444, (err) => {
    if (err) {
        return console.log(err);
    }
    console.log('Server OK');
})


