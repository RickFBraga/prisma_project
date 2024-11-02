import { Request } from "express";

export interface SignUp {
    name: string,
    email: string,
    password: string
}

export interface SignIn {
    email: string,
    password: string
}

export interface CredentialsInterface {
    title: string,
    url: string,
    username: string,
    password: string
}

export interface AuthenticatedRequest extends Request {
    userId?: number;
}
