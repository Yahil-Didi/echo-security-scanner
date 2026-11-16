import { INestApplication, ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

/** Paths served outside the `/api` prefix. */
export const QUEUES_DASHBOARD_PATH = '/admin/queues';
const SWAGGER_PATH = 'docs';

/** HTTP setup used by `main.ts` and by the system tests, so the tests run the real setup. */
export const configureApp = (app: INestApplication): INestApplication => {
  app.setGlobalPrefix('api', { exclude: ['health', QUEUES_DASHBOARD_PATH] });
  app.useGlobalPipes(
    new ValidationPipe({ transform: true, whitelist: true, forbidNonWhitelisted: true }),
  );

  const swaggerConfig = new DocumentBuilder()
    .setTitle('Echo Security Scanner')
    .setDescription('Container image vulnerabilities scanned periodically with Trivy.')
    .setVersion('1.0.0')
    .build();
  const document = SwaggerModule.createDocument(app, swaggerConfig);
  // UI at /docs, raw spec at /docs-json
  SwaggerModule.setup(SWAGGER_PATH, app, document);
  return app;
};
