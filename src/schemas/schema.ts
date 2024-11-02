import Joi from 'joi';
import { CredentialsInterface, SignIn, SignUp } from '../protocols';

export const signUpSchema = Joi.object<SignUp>({
    name: Joi.string().min(3).max(30).required(),
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required()
});

export const signInSchema = Joi.object<SignIn>({
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
});

export const credentialSchema = Joi.object<CredentialsInterface>({
    title: Joi.string().required(),
    url: Joi.string().uri().required(),
    username: Joi.string().required(),
    password: Joi.string().required(),
});


