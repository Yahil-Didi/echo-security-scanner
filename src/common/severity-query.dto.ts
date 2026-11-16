import { Transform } from 'class-transformer';
import { IsArray, IsEnum, IsOptional } from 'class-validator';
import { Severity } from './severity.enum';

export class SeverityQueryDto {
  /**
   * One or more severities, in any case: `?severity=high`, `?severity=CRITICAL,HIGH`,
   * or the parameter repeated.
   */
  @IsOptional()
  // A repeated parameter arrives as an array; String() joins it with commas, so both forms work the
  // same.
  @Transform(({ value }) =>
    String(value)
      .split(',')
      .map((s) => s.trim().toUpperCase())
      .filter(Boolean),
  )
  @IsArray()
  @IsEnum(Severity, {
    each: true,
    message: `severity must be one or more of: ${Object.values(Severity).join(', ')}`,
  })
  severity?: Severity[];
}
