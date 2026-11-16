export * from './image.entity';
export * from './cve.entity';
export * from './image-vulnerability.entity';

import { Cve } from './cve.entity';
import { Image } from './image.entity';
import { ImageVulnerability } from './image-vulnerability.entity';

export const ENTITIES = [Image, Cve, ImageVulnerability];
