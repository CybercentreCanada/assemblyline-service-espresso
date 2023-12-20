import os

import pytest
from assemblyline_service_utilities.common.keytool_parse import keytool_printcert

# Getting absolute paths, names and regexes
TEST_DIR = os.path.dirname(os.path.abspath(__file__))


class TestEspresso:
    @staticmethod
    @pytest.mark.parametrize(
        "cert_path, printcert",
        [(f'{TEST_DIR}/samples/ca.pem',
          'Owner: CN=ca, OU=ca, O=ca, L=ca, ST=ca, C=CA\n'
          'Issuer: CN=root, OU=root, O=root, L=root, ST=root, C=CA\n'
          'Serial number: 5f822698\n'
          'Valid from: Wed Apr 14 17:40:13 UTC 2021 until: Tue Jul 13 17:40:13 UTC 2021\n'
          'Certificate fingerprints:\n'
          '\t SHA1: 59:7C:A0:72:5D:98:9F:61:B9:9F:29:20:C8:73:60:9C:0E:02:EB:DF\n'
          '\t SHA256: AE:56:E7:5E:49:F2:1B:4B:FF:7A:76:12:6E:72:84:1C:6B:D3:E7:FA:D9:84:43:53:C7:24:A9:2F:3E:12:63:7F\n'
          'Signature algorithm name: SHA256withDSA\n'
          'Subject Public Key Algorithm: 2048-bit DSA key\n'
          'Version: 3\n\n'
          'Extensions: \n\n'
          '#1: ObjectId: 2.5.29.35 Criticality=false\n'
          'AuthorityKeyIdentifier [\n'
          'KeyIdentifier [\n'
          '0000: 9D 76 79 BA 97 17 06 07   75 A6 5C E1 E6 98 09 F0  .vy.....u.\\.....\n'
          '0010: D8 42 F6 C1                                        .B..\n'
          ']\n]\n\n'
          '#2: ObjectId: 2.5.29.19 Criticality=false\n'
          'BasicConstraints:[\n'
          '  CA:true\n'
          '  PathLen:0\n]\n\n'
          '#3: ObjectId: 2.5.29.14 Criticality=false\n'
          'SubjectKeyIdentifier [\n'
          'KeyIdentifier [\n'
          '0000: C2 BF E5 BF 85 2B ED 82   D2 F1 49 89 06 5B 5E 90  .....+....I..[^.\n'
          '0010: 64 FC C3 16                                        d...\n]\n]\n\n'),
         (f'{TEST_DIR}/samples/server.pem',
          'Certificate[1]:\n'
          'Owner: CN=server, OU=server, O=server, L=server, ST=server, C=CA\n'
          'Issuer: CN=ca, OU=ca, O=ca, L=ca, ST=ca, C=CA\nSerial number: 4e2d045a\n'
          'Valid from: Wed Apr 14 17:42:22 UTC 2021 until: Tue Jul 13 17:42:22 UTC 2021\n'
          'Certificate fingerprints:\n'
          '\t SHA1: 0B:BE:A7:40:20:F4:F0:DE:D1:C8:99:26:32:A8:33:7A:EB:E8:87:70\n'
          '\t SHA256: 83:C1:8D:49:A4:98:3F:73:66:97:63:78:4C:E5:70:BF:0C:A2:71:4A:58:CE:B0:4E:65:87:39:F0:06:1F:7F:2C\n'
          'Signature algorithm name: SHA256withDSA\n'
          'Subject Public Key Algorithm: 2048-bit DSA key\n'
          'Version: 3\n\n'
          'Extensions: \n\n'
          '#1: ObjectId: 2.5.29.35 Criticality=false\n'
          'AuthorityKeyIdentifier [\n'
          'KeyIdentifier [\n'
          '0000: C2 BF E5 BF 85 2B ED 82   D2 F1 49 89 06 5B 5E 90  .....+....I..[^.\n'
          '0010: 64 FC C3 16                                        d...\n'
          ']\n]\n\n'
          '#2: ObjectId: 2.5.29.15 Criticality=true\n'
          'KeyUsage [\n'
          '  DigitalSignature\n'
          '  Key_Encipherment\n]\n\n'
          '#3: ObjectId: 2.5.29.14 Criticality=false\n'
          'SubjectKeyIdentifier [\n'
          'KeyIdentifier [\n'
          '0000: 9B 06 D8 13 2E 6F 2F 62   85 66 42 A9 AC 86 2E A8  .....o/b.fB.....\n'
          '0010: 25 89 AB FC                                        %...\n'
          ']\n]\n\n\n'
          'Certificate[2]:\n'
          'Owner: CN=ca, OU=ca, O=ca, L=ca, ST=ca, C=CA\n'
          'Issuer: CN=root, OU=root, O=root, L=root, ST=root, C=CA\n'
          'Serial number: 5f822698\n'
          'Valid from: Wed Apr 14 17:40:13 UTC 2021 until: Tue Jul 13 17:40:13 UTC 2021\n'
          'Certificate fingerprints:\n'
          '\t SHA1: 59:7C:A0:72:5D:98:9F:61:B9:9F:29:20:C8:73:60:9C:0E:02:EB:DF\n'
          '\t SHA256: AE:56:E7:5E:49:F2:1B:4B:FF:7A:76:12:6E:72:84:1C:6B:D3:E7:FA:D9:84:43:53:C7:24:A9:2F:3E:12:63:7F\n'
          'Signature algorithm name: SHA256withDSA\n'
          'Subject Public Key Algorithm: 2048-bit DSA key\n'
          'Version: 3\n\n'
          'Extensions: \n\n'
          '#1: ObjectId: 2.5.29.35 Criticality=false\n'
          'AuthorityKeyIdentifier [\n'
          'KeyIdentifier [\n'
          '0000: 9D 76 79 BA 97 17 06 07   75 A6 5C E1 E6 98 09 F0  .vy.....u.\\.....\n'
          '0010: D8 42 F6 C1                                        .B..\n]\n]\n\n'
          '#2: ObjectId: 2.5.29.19 Criticality=false\n'
          'BasicConstraints:[\n'
          '  CA:true\n'
          '  PathLen:0\n]\n\n'
          '#3: ObjectId: 2.5.29.14 Criticality=false\n'
          'SubjectKeyIdentifier [\n'
          'KeyIdentifier [\n'
          '0000: C2 BF E5 BF 85 2B ED 82   D2 F1 49 89 06 5B 5E 90  .....+....I..[^.\n'
          '0010: 64 FC C3 16                                        d...\n]\n]\n\n'),
         (f'{TEST_DIR}/samples/not_a_cert.txt', None),
         (f'{TEST_DIR}/sample/not_exist.pem', None)])
    def test_keytool_printcert(cert_path, printcert):
        """
        keytool_printcert is tested here instead of assemblyline_v4_service because keytool is
        installed on a per service basis.

        The test certificates (ca.pem and server.pem) were created for this test by following the
        steps in the 'Generate Certificates for an SSL Server' section of the keytool docs:
        https://docs.oracle.com/javase/8/docs/technotes/tools/windows/keytool.html
        """
        cert = keytool_printcert(cert_path)
        assert cert == printcert
