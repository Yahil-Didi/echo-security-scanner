import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { DataSourceOptions } from 'typeorm';
import { PostgresConnectionOptions } from 'typeorm/driver/postgres/PostgresConnectionOptions';
import { Env } from '../config/config.schema';
import { ENTITIES } from './entities';
import { InitialSchema1731744000000 } from './migrations/1731744000000-InitialSchema';

type Connection = Pick<
  PostgresConnectionOptions,
  'host' | 'port' | 'username' | 'password' | 'database'
>;

/** Also used by the system tests, so they run with the same entities and migration. */
export const typeOrmOptions = (connection: Connection): DataSourceOptions => ({
  type: 'postgres',
  ...connection,
  entities: ENTITIES,
  migrations: [InitialSchema1731744000000],
  // The migration creates the tables when the app starts; TypeORM never changes them by itself.
  synchronize: false,
  migrationsRun: true,
});

@Module({
  imports: [
    TypeOrmModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService<Env, true>) =>
        typeOrmOptions({
          host: config.get('DB_HOST', { infer: true }),
          port: config.get('DB_PORT', { infer: true }),
          username: config.get('DB_USER', { infer: true }),
          password: config.get('DB_PASSWORD', { infer: true }),
          database: config.get('DB_NAME', { infer: true }),
        }),
    }),
  ],
})
export class DatabaseModule {}
