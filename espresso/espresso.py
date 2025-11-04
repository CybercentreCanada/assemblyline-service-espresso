import hashlib
import logging
import os
import zipfile
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
from subprocess import PIPE, Popen

from assemblyline.common import forge
from assemblyline.common.hexdump import hexdump
from assemblyline.common.str_utils import safe_str, translate_str
from assemblyline_service_utilities.common.keytool_parse import certificate_chain_from_printcert, keytool_printcert
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import BODY_FORMAT, Heuristic, Result, ResultSection
from assemblyline_v4_service.common.utils import set_death_signal
from .file_result import FileResult, ClassAttributes
from javatools.manifest import Manifest

G_LAUNCHABLE_EXTENSIONS = [
    "BAT",  # DOS/Windows batch file
    "CMD",  # Windows Command
    "COM",  # DOS Command
    "EXE",  # DOS/Windows executable
    "DLL",  # Windows library
    "LNK",  # Windows shortcut
    "SCR",  # Windows screensaver
]


Classification = forge.get_classification()


class NotJARException(Exception):
    pass


# noinspection PyBroadException
class Espresso(ServiceBase):
    def __init__(self, config=None):
        super(Espresso, self).__init__(config)
        self.cfr = "/opt/al/support/espresso/cfr.jar"

    @staticmethod
    def get_tool_version(**_):
        return f"CFR: {os.environ.get('CFR_VERSION')}"

    def start(self):
        if not os.path.isfile(self.cfr):
            self.log.error("CFR executable is missing. The service install will most likely failed.")

    def jar_extract(self, filename, dest_dir):
        zf = None
        try:
            zf = zipfile.ZipFile(filename, "r")

            # Make sure this is actually a JAR
            unknown_charset_counter = 0
            for zfname in zf.namelist():
                uni_zfname = ""
                o = None
                try:
                    zf_info = zf.getinfo(zfname)

                    if not zf_info.orig_filename.endswith("\\") and not zf_info.orig_filename.endswith("/"):
                        char_enc_guessed = translate_str(zfname)
                        uni_zfname = char_enc_guessed["converted"]

                        if char_enc_guessed["encoding"] == "unknown":
                            uni_zfname = f"unknown_charset_filename_{unknown_charset_counter}"
                            unknown_charset_counter += 1

                        # creating the directory as problems if the filename
                        # starts with a /, strip it off.
                        if uni_zfname.startswith("/"):
                            uni_zfname = uni_zfname[1:]

                        unzipped_filename = os.path.normpath(os.path.join(dest_dir, uni_zfname))
                        zf_content = zf.read(zfname)

                        if not os.path.exists(os.path.dirname(unzipped_filename)):
                            os.makedirs(os.path.dirname(unzipped_filename))

                        try:
                            o = open(unzipped_filename, "wb")
                        except Exception:
                            # just in case there was invalid char ...
                            uni_zfname = f"unknown_charset_filename_{unknown_charset_counter}"
                            unknown_charset_counter += 1
                            unzipped_filename = os.path.normpath(os.path.join(dest_dir, uni_zfname))
                            o = open(unzipped_filename, "wb")
                        o.write(zf_content)
                except Exception as e:
                    self.log.exception(
                        f"Failed at extracting files from the JAR "
                        f"({filename.encode('utf-8')} :: + {uni_zfname}). Error: {str(e)}"
                    )
                    return False
                finally:
                    if o is not None:
                        try:
                            o.close()
                        except Exception:
                            pass

        except (IOError, zipfile.BadZipfile):
            self.log.info(f"Not a ZIP File or Corrupt ZIP File: {filename}")
            return False
        except NotJARException:
            self.log.info(f"Not a JAR File: {filename}")
            raise NotJARException
        except Exception as e:
            self.log.exception(f"Caught an exception while analysing the file {filename}. [{e}]")
            return False
        finally:
            if zf is not None:
                try:
                    zf.close()
                except Exception:
                    pass

        return True

    def decompile_to_str(self, path_to_file):
        decompiled_path = self.find_decompiled_file(path_to_file)
        if decompiled_path:
            with open(decompiled_path, "rb") as decompiled_file:
                return decompiled_file.read()
        else:
            stdout, _ = Popen(
                ["java", "-jar", self.cfr, path_to_file], stdout=PIPE, stderr=PIPE, preexec_fn=set_death_signal()
            ).communicate()

            if len(stdout) > 0 and b"Decompiled with CFR" in stdout[:0x24]:
                return stdout
            else:
                return None

    def decompile_class_file(self, path_to_file, decompiled_dir, extract_dir):
        # Decompile file
        decompiled = self.decompile_to_str(path_to_file)

        if decompiled:
            decompiled_path = self.find_decompiled_file(path_to_file)
            if not decompiled_path:
                decompiled_path = path_to_file.replace(".class", ".java").replace(".deob", "")
                java_handle = open(decompiled_path, "wb")
                java_handle.write(decompiled)
                java_handle.close()

            desc = f"Decompiled {path_to_file.replace(extract_dir + '/', '').replace(decompiled_dir + '/', '')}"
            name = decompiled_path.replace(extract_dir + "/", "").replace(decompiled_dir + "/", "")
            return decompiled_path, name, desc
        else:
            return None, None, None

    @staticmethod
    def find_decompiled_file(class_file):
        decompiled_file = class_file.replace("_extracted", "_decompiled").replace(".class", ".java")
        if os.path.exists(decompiled_file):
            return decompiled_file
        return None

    def do_class_analysis(self, data):
        interesting_attributes = ClassAttributes.empty_class_attributes()
        interesting_attributes.applet_found = b"java/applet/Applet" in data
        interesting_attributes.classloader_found = b"ClassLoader" in data
        interesting_attributes.security_found = b"/security/" in data
        interesting_attributes.url_found = b"net/URL" in data
        interesting_attributes.runtime_found = b"java/lang/Runtime" in data

        return interesting_attributes

    def validate_certs(self, certs, cur_file):
        """
        This method tags out of a certificate or certificate chain. The start and
        end date, issuer, and owner are all pulled. The certificate itself is included as a
        supplementary file.

        :param certs: the keytool -printcert string representation of a certificate/certificate chain
        :param cur_file: the file path of the certificate
        :return:
        """
        certs = certificate_chain_from_printcert(certs)
        signature_block_certs = []
        output_files = []

        for cert in certs:
            res_cert = ResultSection(
                "Certificate Analysis", body=safe_str(cert.raw), body_format=BODY_FORMAT.MEMORY_DUMP
            )

            res_cert.add_tag("cert.valid.start", cert.valid_from)
            res_cert.add_tag("cert.valid.end", cert.valid_to)
            res_cert.add_tag("cert.issuer", cert.issuer)
            res_cert.add_tag("cert.owner", cert.owner)

            valid_from_splitted = cert.valid_from.split(" ")
            valid_from_year = int(valid_from_splitted[-1])

            valid_to_splitted = cert.valid_to.split(" ")
            valid_to_year = int(valid_to_splitted[-1])

            if cert.owner == cert.issuer:
                ResultSection("Certificate is self-signed", parent=res_cert, heuristic=Heuristic(11))

            if not cert.country:
                ResultSection("Certificate owner has no country", parent=res_cert, heuristic=Heuristic(12))

            if valid_from_year > valid_to_year:
                ResultSection(
                    "Certificate expires before validity date starts", parent=res_cert, heuristic=Heuristic(15)
                )

            if (valid_to_year - valid_from_year) > 30:
                ResultSection("Certificate valid more then 30 years", parent=res_cert, heuristic=Heuristic(13))

            if cert.country:
                try:
                    int(cert.country)
                    is_int_country = True
                except Exception:
                    is_int_country = False

                if len(cert.country) != 2 or is_int_country:
                    ResultSection("Invalid country code in certificate owner", parent=res_cert, heuristic=Heuristic(14))

            signature_block_certs.append(res_cert)

            if len(res_cert.subsections) > 0:
                name = os.path.basename(cur_file)
                desc = f"JAR Signature Block: {name}"
                output_files.append((cur_file.decode("utf-8"), name.decode("utf-8"), desc))

        return signature_block_certs, output_files

    def analyse_meta_information(self, meta_dir):
        """
        this function pulls the meta information out of the META-INF folder.
        For now it analyzes the manifest file and the certificate(s)

        :param meta_dir: the path of the META-INF folder
        :return:
        """
        # iterate over all files in META-INF folder
        mf = Manifest()
        manifest_tags = []
        certs = []
        output_files = []
        for filename in os.listdir(meta_dir):
            cur_file = os.path.join(meta_dir, filename)
            if cur_file.upper().endswith(b"MANIFEST.MF"):  # handle jar manifest
                with open(cur_file, "rb") as manifest_file:
                    # Parse manifest contents for easier data retrieval
                    mf.parse(manifest_file.read())

                # Extract information about the main class
                if mf.get("Main-Class"):
                    main = tuple(mf["Main-Class"].rsplit(".", 1))
                    if len(main) == 2:
                        manifest_tags.append(("file.jar.main_class", main[1]))
                        manifest_tags.append(("file.jar.main_package", main[0]))
                    elif len(main) == 1:
                        manifest_tags.append(("file.jar.main_class", main[0]))

                # Extract information about the packages imported
                for package_str in mf.get("Import-Package", "").split(","):
                    # Assume the package doesn't have a version associated
                    data = package_str
                    if ";" in package_str:
                        # There's a version associated to package, overwrite value before tagging
                        data = package_str.replace(";version", "=").replace('"', "")

                    manifest_tags.append(("file.jar.imported_package", data))

            else:
                stdout = keytool_printcert(cur_file)

                if stdout:  # if stdout isn't None then the file must have been a certificate
                    certs, output_files = self.validate_certs(stdout, cur_file)

        return manifest_tags, certs, output_files

    def decompile_jar(self, path_to_file, target_dir):
        cfr = Popen(
            ["java", "-jar", self.cfr, "--analyseas", "jar", "--outputdir", target_dir, path_to_file],
            stdout=PIPE,
            stderr=PIPE,
            preexec_fn=set_death_signal(),
        )
        cfr.communicate()

    def execute(self, request):
        request.result = Result()
        request.set_service_context(self.get_tool_version())
        temp_filename = request.file_path
        filename = os.path.basename(temp_filename)
        extract_dir = os.path.join(self.working_directory, f"{filename}_extracted")
        decompiled_dir = os.path.join(self.working_directory, f"{filename}_decompiled")

        result_list = []
        extracted_class_files = []
        supplementary_files = []
        important_result_list = []

        # Analysis properties
        classloader_found = 0
        security_found = 0
        url_found = 0
        runtime_found = 0
        applet_found = 0

        manifest_tags = []
        signature_block_certs = []
        unique_headers_and_files = {}
        embedded_pes = []
        launchable_files = []

        # decompile java/jar to the decompiled_dir
        self.decompile_jar(temp_filename, decompiled_dir)
        # extract files in jar
        self.jar_extract(temp_filename, extract_dir)

        # task for analyzing each file
        def analyze_file(root_dir, current_file):
            cur_file_path = os.path.join(root_dir.decode("utf-8"), current_file.decode("utf-8"))

            file_result = FileResult.empty_file_result(cur_file_path)

            with open(cur_file_path, "rb") as cur_file:
                start_bytes = cur_file.read(256)

                ##############################
                # Executables in JAR
                ##############################
                cur_ext = os.path.splitext(current_file)[1][1:].upper()
                if start_bytes[:2] == b"MZ":
                    file_result.embedded_pes = True
                ##############################
                # Launchable in JAR
                ##############################
                elif cur_ext in G_LAUNCHABLE_EXTENSIONS:
                    file_result.launchable_file = True

                ##############################
                # analyze CLASS file
                ##############################
                if cur_file_path.upper().endswith(".CLASS"):
                    # analyze class file
                    if start_bytes[:4] == b"\xca\xfe\xba\xbe":
                        cur_file.seek(0)

                        cur_file_full_data = cur_file.read()

                        # Analyse file for suspicious functions
                        file_result.interesting_class_attributes = self.do_class_analysis(cur_file_full_data)
                        if file_result.interesting_class_attributes.is_interesting():
                            path, name, desc = self.decompile_class_file(cur_file_path, decompiled_dir, extract_dir)
                            if path:
                                file_result.extracted_class_file = (path, name, desc)

                    else:
                        # Could not deobfuscate
                        # store the first 265 byte of file data to identify unique files
                        file_result.header_hex = hexdump(start_bytes)

            return file_result

        # Walk through each file and analyze them separately
        for root_dir, _, files in os.walk(extract_dir.encode("utf-8")):
            logging.info(f"Extracted: {root_dir} - {files}")
            # if the META-INF folder is encountered
            if root_dir.upper().endswith(b"META-INF"):  # only top level meta
                mani_tags, certs, output_files = self.analyse_meta_information(root_dir)
                supplementary_files.extend(output_files)
                manifest_tags.extend(mani_tags)
                signature_block_certs.extend(certs)
                continue
            # analyze each file using a thread pool
            with ThreadPoolExecutor() as executor:
                file_futures = [executor.submit(analyze_file, root_dir, cur_file) for cur_file in files]

                for future in concurrent.futures.as_completed(file_futures):
                    file_result = future.result()

                    classloader_found += int(file_result.interesting_class_attributes.classloader_found)
                    security_found += int(file_result.interesting_class_attributes.security_found)
                    url_found += int(file_result.interesting_class_attributes.url_found)
                    runtime_found += int(file_result.interesting_class_attributes.runtime_found)
                    applet_found += int(file_result.interesting_class_attributes.applet_found)

                    if file_result.header_hex:
                        unique_header_files = unique_headers_and_files.get(file_result.header_hex, list())
                        unique_header_files.append(file_result.file_path)
                        unique_headers_and_files[file_result.header_hex] = unique_header_files

                    if file_result.embedded_pes:
                        embedded_pes.append(file_result.file_path)
                    if file_result.launchable_file:
                        launchable_files.append(file_result.file_path)

                    if file_result.extracted_class_file[0]:
                        extracted_class_files.append(file_result.extracted_class_file)

        # if irregular header byte exist, create result section for each unique header
        for hex_256 in unique_headers_and_files.keys():
            ob_res = dict(
                title_text="Java class file(s) doesn't have the normal class files magic bytes. "
                "The file was re-submitted for analysis. Here are the first 256 bytes:",
                body=hex_256,
                body_format=BODY_FORMAT.MEMORY_DUMP,
                heur_id=Heuristic(3),
                tags=[("file.behavior", "Suspicious Java Class")],
                files=unique_headers_and_files[hex_256],
            )

            important_result_list.append(ob_res)

        # compile embedded files into a single heuristic
        if embedded_pes:
            important_result_list.append(
                dict(
                    title_text="Embedded executable files found. There may be a malicious intent.",
                    heur_id=(Heuristic(1) if applet_found > 0 else Heuristic(2)),
                    tags=[("file.behavior", "Embedded PE")],
                    files=embedded_pes,
                    file_desc="Embedded executable file. ",
                )
            )

        if launchable_files:
            important_result_list.append(
                dict(
                    title_text="Launch-able file type(s) found. There may be a malicious intent.",
                    heur_id=(Heuristic(3) if applet_found > 0 else Heuristic(4)),
                    tags=[("file.behavior", "Launch-able file in JAR")],
                    file_desc="Launchable file. ",
                    files=launchable_files,
                )
            )

        root_analysis_result = ResultSection("Analysis of the JAR file")
        res_meta = ResultSection("[Meta Information]")

        if manifest_tags:
            res_manifest = ResultSection("Manifest File Information Extract", parent=res_meta)
            for tag, val in manifest_tags:
                res_manifest.add_tag(tag, val)

        for res_cert in signature_block_certs:
            res_meta.add_subsection(res_cert)

        if res_meta.subsections:
            root_analysis_result.add_subsection(res_meta)

        if runtime_found > 0 or applet_found > 0 or classloader_found > 0 or security_found > 0 or url_found > 0:
            root_analysis_result.add_line("All suspicious class files were saved as supplementary files.")

        res_class = ResultSection("[Suspicious classes]")

        if runtime_found > 0:
            ResultSection(
                "Runtime Found",
                body=f"java/lang/Runtime: {runtime_found}",
                heuristic=Heuristic(10),
                parent=res_class,
            )

        if applet_found > 0:
            ResultSection(
                "Applet Found",
                body=f"java/applet/Applet: {applet_found}",
                heuristic=Heuristic(6),
                parent=res_class,
            )

        if classloader_found > 0:
            ResultSection(
                "Classloader Found",
                body=f"java/lang/ClassLoader: {classloader_found}",
                heuristic=Heuristic(7),
                parent=res_class,
            )

        if security_found > 0:
            ResultSection(
                "Security Found",
                body=f"java/security/*: {security_found}",
                heuristic=Heuristic(8),
                parent=res_class,
            )

        if url_found > 0:
            ResultSection(
                "URL Found", body=f"java/net/URL: {url_found}", heuristic=Heuristic(9), parent=root_analysis_result
            )

        if res_class.subsections:
            result_list.append(res_class)

        if root_analysis_result.subsections:
            result_list.append(root_analysis_result)

        # attach result section to relevant files. Get interesting files to add to extracted
        important_output_files = self.recurse_add_result(request.result, important_result_list)

        for desc, file in important_output_files:
            file_description = desc + f"Extracted from 'JAR' file {filename}"
            request.add_extracted(
                file,
                file.replace(extract_dir + "/", "").replace(decompiled_dir + "/", ""),
                file_description,
                safelist_interface=self.api_interface,
            )
        # put as many decompiled class file in extracted as possible and leave the rest in supplementary
        max_extracted = (request.task.max_extracted - len(important_output_files)) - 1
        sorted_class_files = sorted(list(set(extracted_class_files)))
        max_class_extracted = 0 if max_extracted < 0 else len(sorted_class_files)

        for path, name, desc in sorted_class_files[:max_class_extracted]:
            request.add_extracted(path, name, desc, safelist_interface=self.api_interface)

        supplementary_files.extend(sorted_class_files[max_class_extracted:])
        for path, name, desc in supplementary_files:
            request.add_supplementary(path, name, desc)

        for res in result_list:
            request.result.add_section(res)

    def recurse_add_result(self, request_result, result_list, parent=None):
        output_files = []

        file_set = set()

        for result_desc in result_list:
            res = ResultSection(
                result_desc["title_text"],
                classification=result_desc.get("classification", Classification.UNRESTRICTED),
                parent=parent,
                body_format=result_desc.get("body_format", BODY_FORMAT.TEXT),
                heuristic=result_desc["heur_id"],
            )

            # Add Tags
            tags = result_desc.get("tags", [])
            for res_tag in tags:
                res.add_tag(res_tag[0], res_tag[1])

            # Add body
            body = result_desc.get("body", None)
            if body:
                res.set_body(body)

            # File for resubmit
            files = result_desc.get("files", [])
            desc = result_desc.get("file_desc", "")
            for res_file in files:
                # make sure we are only adding unique file
                if res_file in file_set:
                    continue
                output_files.append((desc, res_file))
                file_set.add(res_file)

            # Add to file res if root result
            if parent is None:
                request_result.add_section(res)

        return output_files
