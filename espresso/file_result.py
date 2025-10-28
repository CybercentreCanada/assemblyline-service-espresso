from dataclasses import dataclass
from typing import Tuple


@dataclass
class ClassAttributes():
    applet_found: bool
    classloader_found: bool
    security_found: bool
    url_found: bool
    runtime_found: bool

    def is_interesting(self):
        return self.applet_found or self.classloader_found or self.security_found \
            or self.url_found or self.runtime_found

    @staticmethod
    def empty_class_attributes():
        return ClassAttributes(False, False, False, False, False)


@dataclass
class FileResult():
    file_path: str
    embedded_pes: bool
    launchable_file: bool
    interesting_class_attributes: ClassAttributes
    header_hex: str
    extracted_class_file: Tuple
    empty_file: bool

    @staticmethod
    def empty_file_result(file_path):
        return FileResult(
            file_path=file_path,
            embedded_pes=False,
            launchable_file=False,
            interesting_class_attributes=ClassAttributes.empty_class_attributes(),
            header_hex="",
            extracted_class_file=(None, None, None),
            empty_file=False,
        )
