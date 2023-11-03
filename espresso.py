import hashlib
import logging
import os
import zipfile
from concurrent.futures import ThreadPoolExecutor
from subprocess import PIPE, Popen

from assemblyline.common import forge
from assemblyline.common.hexdump import hexdump
from assemblyline.common.str_utils import safe_str, translate_str
from assemblyline.odm.models.result import BODY_FORMAT
from assemblyline_service_utilities.common.keytool_parse import certificate_chain_from_printcert, keytool_printcert
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Heuristic, Result, ResultSection
from assemblyline_v4_service.common.utils import set_death_signal

G_LAUNCHABLE_EXTENSIONS = [
    "BAT",  # DOS/Windows batch file
    "CMD",  # Windows Command
    "COM",  # DOS Command
    "EXE",  # DOS/Windows executable
    "DLL",  # Windows library
    "LNK",  # Windows shortcut
    "SCR",  # Windows screensaver
]

APPLET = "applet"
APPLET_MZ = "mz_in_applet"

Classification = forge.get_classification()


class NotJARException(Exception):
    pass


# noinspection PyBroadException
class Espresso(ServiceBase):
    def __init__(self, config=None):
        super(Espresso, self).__init__(config)
        self.cfr = "/opt/al/support/espresso/cfr.jar"
        self.applet_found = 0
        self.classloader_found = 0
        self.security_found = 0
        self.url_found = 0
        self.runtime_found = 0
        self.manifest_tags = None
        self.signature_block_certs = None

    @staticmethod
    def get_tool_version(**_):
        return "CFR: 0.151"

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
        except Exception as e:
            if type(e) == NotJARException:
                self.log.info(f"Not a JAR File: {filename}")
                raise

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

    def decompile_class(self, path_to_file, new_files, decompiled_dir, extract_dir):
        # Decompile file
        decompiled = self.decompile_to_str(path_to_file)

        if decompiled:
            decompiled_path = self.find_decompiled_file(path_to_file)
            if not decompiled_path:
                decompiled_path = path_to_file.replace(".class", ".java").replace(".deob", "")
                java_handle = open(decompiled_path, "wb")
                java_handle.write(decompiled)
                java_handle.close()

            txt = f"Decompiled {path_to_file.replace(extract_dir + '/', '').replace(decompiled_dir + '/', '')}"
            name = decompiled_path.replace(extract_dir + "/", "").replace(decompiled_dir + "/", "")
            new_files.append((decompiled_path, name, txt))
            return len(decompiled), hashlib.sha1(decompiled).hexdigest(), os.path.basename(decompiled_path)
        else:
            return 0, "", ""

    @staticmethod
    def find_decompiled_file(class_file):
        decompiled_file = class_file.replace("_extracted", "_decompiled").replace(".class", ".java")
        if os.path.exists(decompiled_file):
            return decompiled_file
        return None

    def do_class_analysis(self, data):
        has_interesting_attributes = False
        if b"java/applet/Applet" in data:
            self.applet_found += 1
            has_interesting_attributes = True

        if b"ClassLoader" in data:
            self.classloader_found += 1
            has_interesting_attributes = True

        if b"/security/" in data:
            self.security_found += 1
            has_interesting_attributes = True

        if b"net/URL" in data:
            self.url_found += 1
            has_interesting_attributes = True

        if b"java/lang/Runtime" in data:
            self.runtime_found += 1
            has_interesting_attributes = True

        return has_interesting_attributes

    # noinspection PyUnusedLocal
    def analyse_class_file(
        self,
        file_res,
        cf,
        cur_file,
        cur_file_path,
        start_bytes,
        imp_res_list,
        supplementary_files,
        decompiled_dir,
        extract_dir,
    ):
        if start_bytes[:4] == b"\xCA\xFE\xBA\xBE":
            cur_file.seek(0)
            cur_file_full_data = cur_file.read()

            # Analyse file for suspicious functions
            if self.do_class_analysis(cur_file_full_data):
                self.decompile_class(cur_file_path, supplementary_files, decompiled_dir, extract_dir)

        else:
            # Could not deobfuscate
            cur_file.seek(0)
            first_256 = cur_file.read(256)

            ob_res = dict(
                title_text=f"Class file {cf} doesn't have the normal class files magic bytes. "
                "The file was re-submitted for analysis. Here are the first 256 bytes:",
                body=hexdump(first_256),
                body_format=BODY_FORMAT.MEMORY_DUMP,
                heur_id=3,
                tags=[("file.behavior", "Suspicious Java Class")],
                files=[cur_file_path],
            )
            imp_res_list.append(ob_res)

    def validate_certs(self, certs, cur_file, supplementary_files):
        """
        This method tags out of a certificate or certificate chain. The start and
        end date, issuer, and owner are all pulled. The certificate itself is included as a
        supplementary file.

        :param certs: the keytool -printcert string representation of a certificate/certificate chain
        :param cur_file: the file path of the certificate (to be used in supplementary_files)
        :param supplementary_files: the services supplementary files
        :return:
        """
        certs = certificate_chain_from_printcert(certs)

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

            self.signature_block_certs.append(res_cert)

            if len(res_cert.subsections) > 0:
                name = os.path.basename(cur_file)
                desc = f"JAR Signature Block: {name}"
                supplementary_files.append((cur_file.decode("utf-8"), name.decode("utf-8"), desc))

    def analyse_meta_information(self, file_res, meta_dir, supplementary_files, extract_dir):
        """
        this function pulls the meta information out of the META-INF folder.
        For now it analyzes the manifest file and the certificate(s)

        :param file_res: the service response
        :param meta_dir: the path of the META-INF folder
        :param supplementary_files: the service's supplementary files
        :param extract_dir: where the jar archive was extracted to
        :return:
        """
        # iterate over all files in META-INF folder
        for filename in os.listdir(meta_dir):
            cur_file = os.path.join(meta_dir, filename)
            if cur_file.upper().endswith(b"MANIFEST.MF"):  # handle jar manifest
                with open(cur_file, "rb") as manifest_file:
                    lines = []
                    for line in manifest_file:
                        if line.startswith((b" ", b"\t")):
                            lines[-1] += line.strip()
                        else:
                            lines.append(line.rstrip())

                    # pull field/value pairs out of manifest file
                    fields = [tuple(line.split(b": ")) for line in lines if b":" in line]
                    for f in fields:
                        if len(f) != 2:
                            continue
                        if f[0].upper() == b"MAIN-CLASS":  # for now only main-class info extracted
                            main = tuple(f[1].rsplit(b".", 1))
                            if len(main) == 2:
                                self.manifest_tags.append(("file.jar.main_class", main[1]))
                                self.manifest_tags.append(("file.jar.main_package", main[0]))
                            elif len(main) == 1:
                                self.manifest_tags.append(("file.jar.main_class", main[0]))

            else:
                stdout = keytool_printcert(cur_file)
                if stdout:  # if stdout isn't None then the file must have been a certificate
                    self.validate_certs(stdout, cur_file, supplementary_files)

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
        file_res = request.result
        new_files = []
        supplementary_files = []
        imp_res_list = []
        res_list = []

        if request.file_type == "java/jar":
            self.decompile_jar(temp_filename, decompiled_dir)
            if self.jar_extract(temp_filename, extract_dir):
                # Analysis properties
                self.classloader_found = 0
                self.security_found = 0
                self.url_found = 0
                self.runtime_found = 0
                self.applet_found = 0

                self.manifest_tags = []
                self.signature_block_certs = []

                def analyze_file(root, cf, file_res, imp_res_list, supplementary_files, decompiled_dir, extract_dir):
                    cur_file_path = os.path.join(root.decode("utf-8"), cf.decode("utf-8"))
                    with open(cur_file_path, "rb") as cur_file:
                        start_bytes = cur_file.read(24)

                        ##############################
                        # Executables in JAR
                        ##############################
                        cur_ext = os.path.splitext(cf)[1][1:].upper()
                        if start_bytes[:2] == b"MZ":
                            mz_res = dict(
                                title_text=f"Embedded executable file found: {cf} " "There may be a malicious intent.",
                                heur_id=1,
                                tags=[("file.behavior", "Embedded PE")],
                                score_condition=APPLET_MZ,
                            )
                            imp_res_list.append(mz_res)

                        ##############################
                        # Launchable in JAR
                        ##############################
                        elif cur_ext in G_LAUNCHABLE_EXTENSIONS:
                            l_res = dict(
                                title_text=f"Launch-able file type found: {cf}" "There may be a malicious intent.",
                                heur_id=2,
                                tags=[("file.behavior", "Launch-able file in JAR")],
                                score_condition=APPLET_MZ,
                            )
                            imp_res_list.append(l_res)

                        if cur_file_path.upper().endswith(".CLASS"):
                            self.analyse_class_file(
                                file_res,
                                cf,
                                cur_file,
                                cur_file_path,
                                start_bytes,
                                imp_res_list,
                                supplementary_files,
                                decompiled_dir,
                                extract_dir,
                            )

                for root, _, files in os.walk(extract_dir.encode("utf-8")):
                    logging.info(f"Extracted: {root} - {files}")

                    # if the META-INF folder is encountered
                    if root.upper().endswith(b"META-INF"):  # only top level meta
                        self.analyse_meta_information(file_res, root, supplementary_files, extract_dir)
                        continue

                    with ThreadPoolExecutor() as executor:
                        for cf in files:
                            executor.submit(
                                analyze_file,
                                root,
                                cf,
                                file_res,
                                imp_res_list,
                                supplementary_files,
                                decompiled_dir,
                                extract_dir,
                            )

                res = ResultSection("Analysis of the JAR file")

                res_meta = ResultSection("[Meta Information]")
                if len(self.manifest_tags) > 0:
                    res_manifest = ResultSection("Manifest File Information Extract", parent=res_meta)
                    for tag, val in self.manifest_tags:
                        res_manifest.add_tag(tag, val)

                for res_cert in self.signature_block_certs:
                    res_meta.add_subsection(res_cert)

                if res_meta.subsections:
                    res.add_subsection(res_meta)

                if (
                    self.runtime_found > 0
                    or self.applet_found > 0
                    or self.classloader_found > 0
                    or self.security_found > 0
                    or self.url_found > 0
                ):
                    res.add_line("All suspicious class files were saved as supplementary files.")

                res_class = ResultSection("[Suspicious classes]")

                if self.runtime_found > 0:
                    ResultSection(
                        "Runtime Found",
                        body=f"java/lang/Runtime: {self.runtime_found}",
                        heuristic=Heuristic(10),
                        parent=res_class,
                    )

                if self.applet_found > 0:
                    ResultSection(
                        "Applet Found",
                        body=f"java/applet/Applet: {self.applet_found}",
                        heuristic=Heuristic(6),
                        parent=res_class,
                    )

                if self.classloader_found > 0:
                    ResultSection(
                        "Classloader Found",
                        body=f"java/lang/ClassLoader: {self.classloader_found}",
                        heuristic=Heuristic(7),
                        parent=res_class,
                    )

                if self.security_found > 0:
                    ResultSection(
                        "Security Found",
                        body=f"java/security/*: {self.security_found}",
                        heuristic=Heuristic(8),
                        parent=res_class,
                    )

                if self.url_found > 0:
                    ResultSection(
                        "URL Found", body=f"java/net/URL: {self.url_found}", heuristic=Heuristic(9), parent=res_class
                    )

                if res_class.subsections:
                    res.add_subsection(res_class)

                if res.subsections:
                    res_list.append(res)

        # Add results if any
        self.recurse_add_res(file_res, imp_res_list, new_files)
        for res in res_list:
            file_res.add_section(res)

        # Submit embedded files
        if len(new_files) > 0:
            new_files = sorted(list(set(new_files)))
            txt = f"Extracted from 'JAR' file {filename}"
            for embed in new_files:
                request.add_extracted(
                    embed,
                    embed.replace(extract_dir + "/", "").replace(decompiled_dir + "/", ""),
                    txt,
                    safelist_interface=self.api_interface,
                )

        if len(supplementary_files) > 0:
            supplementary_files = sorted(list(set(supplementary_files)))
            for path, name, desc in supplementary_files:
                request.add_supplementary(path, name, desc)

    def recurse_add_res(self, file_res, res_list, new_files, parent=None):
        for res_dic in res_list:
            # Check if condition is OK
            if self.pass_condition(res_dic.get("condition", None)):
                res = ResultSection(
                    res_dic["title_text"],
                    classification=res_dic.get("classification", Classification.UNRESTRICTED),
                    parent=parent,
                    body_format=res_dic.get("body_format", BODY_FORMAT.TEXT),
                )
                heur_id = self.heuristic_alteration(res_dic.get("score_condition", None), res_dic["heur_id"])
                res.set_heuristic(heur_id)

                # Add Tags
                tags = res_dic.get("tags", [])
                for res_tag in tags:
                    res.add_tag(res_tag[0], res_tag[1])

                # Add body
                body = res_dic.get("body", None)
                if body:
                    res.set_body(body)

                # File for resubmit
                files = res_dic.get("files", [])
                for res_file in files:
                    if isinstance(res_file, tuple):
                        res_file = res_file[1]
                    new_files.append(res_file)

                # Add to file res if root result
                if parent is None:
                    file_res.add_section(res)

    def pass_condition(self, condition):
        if condition is None:
            return True
        if condition == APPLET:
            if self.applet_found > 0:
                return True

        return False

    def heuristic_alteration(self, score_condition, heur_id):
        if score_condition is None:
            return heur_id
        if score_condition == APPLET_MZ:
            if self.applet_found > 0:
                return heur_id
            else:
                return heur_id + 1
