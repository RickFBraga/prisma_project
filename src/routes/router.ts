import { Router } from 'express';
import { signUp, signIn, Credentials, updateCredential, deleteCredential, getAllCredentials, getCredentialById, eraseAllCredentials } from '../controllers';
import { authenticateToken, validateSchema } from '../middlewares/validate';
import { credentialSchema, signInSchema, signUpSchema } from '../schemas/schema';

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
