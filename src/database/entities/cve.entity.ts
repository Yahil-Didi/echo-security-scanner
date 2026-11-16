import { Column, Entity, PrimaryColumn } from 'typeorm';
import { Severity } from '../../common/severity.enum';

@Entity('cves')
export class Cve {
  /** Natural key: the vulnerability ID, e.g. CVE-2021-23017 or GHSA-... */
  @PrimaryColumn({ type: 'varchar', length: 64 })
  id: string;

  @Column({ type: 'enum', enum: Severity, default: Severity.UNKNOWN })
  severity: Severity;

  @Column({ type: 'text', nullable: true })
  title: string | null;
}
