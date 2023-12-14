import json
import os
import shutil

import pytest
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline_service_utilities.common.keytool_parse import keytool_printcert
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.task import Task

# Getting absolute paths, names and regexes
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(TEST_DIR)
SERVICE_CONFIG_NAME = "service_manifest.yml"
SERVICE_CONFIG_PATH = os.path.join(ROOT_DIR, SERVICE_CONFIG_NAME)
TEMP_SERVICE_CONFIG_PATH = os.path.join("/tmp", SERVICE_CONFIG_NAME)

# Samples that we will be sending to the service
sample1 = dict(
    sid=1,
    metadata={},
    service_name='espresso',
    service_config={},
    fileinfo=dict(
        magic='Zip archive data, at least v2.0 to extract Zip archive data, made by v2.0, extract using at least '
              'v2.0, last modified Fri Nov 22 13:25:57 2013, uncompressed size 239, method=deflate',
        md5='762c340965c408900af83290a0c638b4',
        mime='application/zip',
        sha1='c727718ef0b7314979ddef22058c35022b7caedc',
        sha256='121723c86cb7b24ad90f68dde901fe6dec0e337d8d3233cd5ef0d58f07d47487',
        size=4092,
        type='java/jar',
    ),
    filename='121723c86cb7b24ad90f68dde901fe6dec0e337d8d3233cd5ef0d58f07d47487',
    min_classification='TLP:W',
    max_files=501,  # TODO: get the actual value
    ttl=3600,
)


@pytest.fixture
def class_instance():
    temp_service_config_path = os.path.join("/tmp", SERVICE_CONFIG_NAME)
    try:
        # Placing the service_manifest.yml in the tmp directory
        shutil.copyfile(SERVICE_CONFIG_PATH, temp_service_config_path)

        from espresso import Espresso
        yield Espresso()
    finally:
        # Delete the service_manifest.yml
        os.remove(temp_service_config_path)


class TestEspresso:

    @classmethod
    def setup_class(cls):
        # Placing the samples in the tmp directory
        samples_path = os.path.join(TEST_DIR, "samples")
        for sample in os.listdir(samples_path):
            sample_path = os.path.join(samples_path, sample)
            shutil.copyfile(sample_path, os.path.join("/tmp", sample))

    @classmethod
    def teardown_class(cls):
        # Cleaning up the tmp directory
        samples_path = os.path.join(TEST_DIR, "samples")
        for sample in os.listdir(samples_path):
            temp_sample_path = os.path.join("/tmp", sample)
            os.remove(temp_sample_path)

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

    @staticmethod
    @pytest.mark.parametrize("sample",
                             [
                                 sample1
                             ])
    def test_execute(class_instance, sample):
        # Creating the required objects for execution
        service_task = ServiceTask(sample1)
        task = Task(service_task)
        class_instance._task = task
        service_request = ServiceRequest(task)

        # Actually executing the sample
        class_instance.execute(service_request)

        # Get the result of execute() from the test method
        test_result = task.get_service_result()

        # Get the assumed "correct" result of the sample
        correct_result_path = os.path.join(TEST_DIR, "results", task.file_name + ".json")
        with open(correct_result_path, "r") as f:
            correct_result = json.loads(f.read())

        # Assert that the appropriate sections of the dict are equal

        # Avoiding date in the response
        test_result_response = test_result.pop("response")
        correct_result_response = correct_result.pop("response")
        assert test_result == correct_result

        # Comparing everything in the response except for the date
        test_result_response.pop("milestones")
        test_result_response["supplementary"][0].pop("path")
        correct_result_response.pop("milestones")
        correct_result_response["supplementary"][0].pop("path")

        assert test_result_response == correct_result_response
