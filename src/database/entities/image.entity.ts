import { Column, Entity, PrimaryGeneratedColumn, Unique } from 'typeorm';

export enum ScanStatus {
  PENDING = 'PENDING',
  SCANNING = 'SCANNING',
  SUCCESS = 'SUCCESS',
  FAILED = 'FAILED',
}

@Entity('images')
@Unique('uq_images_name_tag', ['name', 'tag'])
export class Image {
  @PrimaryGeneratedColumn()
  id: number;

  @Column({ type: 'varchar', length: 255 })
  name: string;

  @Column({ type: 'varchar', length: 128 })
  tag: string;

  @Column({ name: 'scan_status', type: 'enum', enum: ScanStatus, default: ScanStatus.PENDING })
  scanStatus: ScanStatus;

  /** When the last scan attempt finished, successfully or not. */
  @Column({ name: 'last_scanned_at', type: 'timestamptz', nullable: true })
  lastScannedAt: Date | null;

  /** Why the last scan failed (null after a successful scan). */
  @Column({ name: 'last_error', type: 'text', nullable: true })
  lastError: string | null;
}
