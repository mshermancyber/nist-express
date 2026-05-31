import { Router } from 'express';
import { selfAttestAsvs } from '../engine/asvs';

export const asvsRouter = Router();

asvsRouter.get('/', (_req, res) => res.json(selfAttestAsvs()));
