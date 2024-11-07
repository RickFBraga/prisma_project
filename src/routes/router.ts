import { Router } from 'express';
import { Credentials, updateCredential, deleteCredential, getAllCredentials, getCredentialById, eraseAllCredentials } from '../controllers/credentials';
import { authenticateToken, validateSchema } from '../middlewares/validate';
import { credentialSchema, signInSchema, signUpSchema } from '../schemas/schema';
import { signIn } from '../controllers/auth/signIn'
import { signUp } from '../controllers/auth/signUp';

const router = Router();

router.post('/signUp', validateSchema(signUpSchema), signUp);

router.post('/signIn', validateSchema(signInSchema), signIn);

router.post('/credentials', authenticateToken, validateSchema(credentialSchema), Credentials);

router.get('/credentials', authenticateToken, getAllCredentials);

router.get('/credentials/:id', authenticateToken, getCredentialById);

router.put('/credentials/:id', authenticateToken, validateSchema(credentialSchema), updateCredential);

router.delete('/credentials/:id', authenticateToken, deleteCredential);

router.delete("/erase", authenticateToken, eraseAllCredentials);

export default router;
