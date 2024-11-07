import { Response, NextFunction } from "express";
import { AuthenticatedRequest, CredentialsInterface } from "../protocols";
import { PrismaClient, Credential } from "@prisma/client";
import Cryptr from "cryptr";
import dotenv from 'dotenv';

dotenv.config();

const prisma = new PrismaClient();
const encryptedKey = process.env.ENCRYPTION_KEY;

if (!encryptedKey) {
    throw new Error("ENCRYPTION_KEY is not defined in the environment variables");
}
const cryptr = new Cryptr(encryptedKey);

export const Credentials = async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    const { password, title, url, username }: CredentialsInterface = req.body;

    try {
        if (req.userId === undefined) {
            return next({ status: 400, message: "User ID is required" });
        }

        const existingCredential = await prisma.credential.findFirst({
            where: {
                title,
                userId: req.userId
            }
        });

        if (existingCredential) {
            return next({ status: 409, message: "Conflict" });
        }

        const encryptedPassword = cryptr.encrypt(password);

        const newCredential: Credential = await prisma.credential.create({
            data: {
                title,
                url,
                username,
                password: encryptedPassword,
                userId: req.userId
            }
        });

        res.status(201).json(newCredential);
    } catch (error) {
        next(error);
    }
};

export const getAllCredentials = async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    try {
        const credentials: Credential[] = await prisma.credential.findMany({
            where: {
                userId: req.userId
            }
        });

        const decryptedCredentials = credentials.map(credential => ({
            ...credential,
            password: cryptr.decrypt(credential.password)
        }));

        res.status(200).json(decryptedCredentials);
    } catch (error) {
        next(error);
    }
};

export const getCredentialById = async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    const { id } = req.params;

    try {
        const credential: Credential | null = await prisma.credential.findUnique({
            where: {
                id: Number(id),
                userId: req.userId
            }
        });

        if (!credential) {
            return next({ status: 404, message: "Credential Not Found" });
        }

        const decryptedCredential = {
            ...credential,
            password: cryptr.decrypt(credential.password)
        };

        res.status(200).json(decryptedCredential);
    } catch (error) {
        next(error);
    }
};

export const updateCredential = async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    const { id } = req.params;
    const { title, url, username, password }: CredentialsInterface = req.body;

    try {
        const existingCredential: Credential | null = await prisma.credential.findUnique({
            where: { id: Number(id) }
        });

        if (!existingCredential) {
            return next({ status: 404, message: "Credential Not Found" });
        }

        const encryptedPassword = cryptr.encrypt(password);

        await prisma.credential.update({
            where: { id: Number(id) },
            data: {
                title,
                url,
                username,
                password: encryptedPassword,
                userId: req.userId
            }
        });

        res.status(204).send();
    } catch (error) {
        next(error);
    }
};

export const deleteCredential = async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    const { id } = req.params;

    try {
        const existingCredential: Credential | null = await prisma.credential.findUnique({
            where: { id: Number(id) }
        });

        if (!existingCredential) {
            return next({ status: 404, message: "Credential Not Found" });
        }

        await prisma.credential.delete({
            where: { id: Number(id) }
        });

        res.status(204).send();
    } catch (error) {
        next(error);
    }
};

export const eraseAllCredentials = async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    try {
        if (!req.userId) {
            return next({ status: 400, message: "User ID is required" });
        }

        await prisma.credential.deleteMany({
            where: {
                userId: req.userId
            }
        });

        res.status(204).send();
    } catch (error) {
        next(error);
    }
};
