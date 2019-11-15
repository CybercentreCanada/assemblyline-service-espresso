import hashlib
import logging
import os
import zipfile
from subprocess import PIPE, Popen

from assemblyline.common import forge
from assemblyline.common.hexdump import hexdump
from assemblyline.common.str_utils import translate_str
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT
from assemblyline_v4_service.common.utils import set_death_signal

G_LAUNCHABLE_EXTENSIONS = [
    'BAT',  # DOS/Windows batch file
    'CMD',  # Windows Command
    'COM',  # DOS Command
    'EXE',  # DOS/Windows executable
    'DLL',  # Windows library
    'LNK',  # Windows shortcut
    'SCR'   # Windows screensaver
]

APPLET = 'applet'
APPLET_MZ = 'mz_in_applet'

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

    def get_tool_version(self):
        return "CFR: 0.110"

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
                try:
                    zf_info = zf.getinfo(zfname)

                    if not zf_info.orig_filename.endswith('\\') and not zf_info.orig_filename.endswith('/'):
                        char_enc_guessed = translate_str(zfname)
                        uni_zfname = char_enc_guessed['converted']

                        if char_enc_guessed['encoding'] == 'unknown':
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
                            o = open(unzipped_filename, 'wb')
                        except:
                            # just in case there was invalid char ...
                            uni_zfname = f"unknown_charset_filename_{unknown_charset_counter}"
                            unknown_charset_counter += 1
                            unzipped_filename = os.path.normpath(os.path.join(dest_dir, uni_zfname))
                            o = open(unzipped_filename, 'wb')
                        o.write(zf_content)
                except Exception as e:
                    self.log.exception(f"Failed at extracting files from the JAR "
                                       f"({filename.encode('utf-8') + '::' + uni_zfname}). Error: {e}")
                    return False
                finally:
                    try:
                        o.close()
                    except:
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
            try:
                zf.close()
            except:
                pass

        return True

    def decompile_to_str(self, path_to_file):
        decompiled_path = self.find_decompiled_file(path_to_file)
        if decompiled_path:
            with open(decompiled_path, "rb") as decompiled_file:
                return decompiled_file.read()
        else:
            stdout, _ = Popen(["java", "-jar", self.cfr, path_to_file],
                        stdout=PIPE, stderr=PIPE, preexec_fn=set_death_signal()).communicate()

            if len(stdout) > 0 and "Decompiled with CFR" in stdout[:0x24]:
                return stdout
            else:
                return None

    def decompile_class(self, path_to_file, new_files):
        # Decompile file
        decompiled = self.decompile_to_str(path_to_file)

        if decompiled:
            decompiled_path = self.find_decompiled_file(path_to_file)
            if not decompiled_path:
                decompiled_path = path_to_file.replace(".class", ".java").replace(".deob", "")
                java_handle = open(decompiled_path, "wb")
                java_handle.write(decompiled)
                java_handle.close()

            new_files.append((path_to_file, decompiled_path))
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
        if "java/applet/Applet" in data:
            self.applet_found += 1
            has_interesting_attributes = True

        if "ClassLoader" in data:
            self.classloader_found += 1
            has_interesting_attributes = True

        if "/security/" in data:
            self.security_found += 1
            has_interesting_attributes = True

        if "net/URL" in data:
            self.url_found += 1
            has_interesting_attributes = True

        if "java/lang/Runtime" in data:
            self.runtime_found += 1
            has_interesting_attributes = True

        return has_interesting_attributes

    # noinspection PyUnusedLocal
    def analyse_class_file(self, file_res, cf, cur_file, cur_file_path, start_bytes, imp_res_list, supplementary_files):
        if start_bytes[:4] == "\xCA\xFE\xBA\xBE":
            cur_file.seek(0)
            cur_file_full_data = cur_file.read()

            # Analyse file for suspicious functions
            if self.do_class_analysis(cur_file_full_data):
                self.decompile_class(cur_file_path, supplementary_files)

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
                tags=[('file.behaviour', "Suspicious Java Class")],
                files=[cur_file_path],
            )
            imp_res_list.append(ob_res)


    def decompile_jar(self, path_to_file, target_dir):
        cfr = Popen(["java", "-jar", self.cfr, "--analyseas", "jar", "--outputdir", target_dir, path_to_file],
                    stdout=PIPE, stderr=PIPE, preexec_fn=set_death_signal())
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

                for root, _, files in os.walk(extract_dir.encode('utf-8')):
                    logging.info(f"Extracted: {root} - {files}")
                    for cf in files:
                        cur_file_path = os.path.join(root.decode('utf-8'), cf.decode('utf-8'))
                        cur_file = open(cur_file_path, "rb")
                        start_bytes = cur_file.read(24)

                        ##############################
                        # Executables in JAR
                        ##############################
                        cur_ext = os.path.splitext(cf)[1][1:].upper()
                        if start_bytes[:2] == "MZ":
                            mz_res = dict(
                                title_text=f"Embedded executable file found: {cf} "
                                           "There may be a malicious intent.",
                                heur_id=1,
                                tags=[('file.behaviour', "Embedded PE")],
                                score_condition=APPLET_MZ,
                            )
                            imp_res_list.append(mz_res)

                        ##############################
                        # Launchable in JAR
                        ##############################
                        elif cur_ext in G_LAUNCHABLE_EXTENSIONS:
                            l_res = dict(
                                title_text=f"Launch-able file type found: {cf}"
                                           "There may be a malicious intent.",
                                heur_id=2,
                                tags=[('file.behaviour', "Launch-able file in JAR")],
                                score_condition=APPLET_MZ,
                            )
                            imp_res_list.append(l_res)

                        if cur_file_path.upper().endswith('.CLASS'):
                            self.analyse_class_file(file_res, cf, cur_file, cur_file_path,
                                                    start_bytes, imp_res_list, supplementary_files)

                        try:
                            cur_file.close()
                        except:
                            pass

                res = ResultSection("Analysis of the JAR file")

                #Add file Analysis results to the list
                heuristic_set = False
                if self.runtime_found > 0:
                    res.set_heuristic(10)
                    heuristic_set = True
                if self.applet_found > 0:
                    res.set_heuristic(6)
                    heuristic_set = True
                if self.classloader_found > 0:
                    res.set_heuristic(7)
                    heuristic_set = True
                if self.security_found > 0:
                    res.set_heuristic(8)
                    heuristic_set = True
                if self.url_found > 0:
                    res.set_heuristic(9)
                    heuristic_set = True

                if heuristic_set:
                    res.add_line("All suspicious class files where saved as supplementary files.")
                res_class = ResultSection("[Suspicious classes]", parent=res)
                res_class.add_line(f"java/lang/Runtime: {self.runtime_found}")
                res_class.add_line(f"java/applet/Applet: {self.applet_found}")
                res_class.add_line(f"java/lang/ClassLoader: {self.classloader_found}")
                res_class.add_line(f"java/security/*: {self.security_found}")
                res_class.add_line(f"java/net/URL: {self.url_found}")
                res_list.append(res)

        # Add results if any
        self.recurse_add_res(file_res, imp_res_list, new_files)
        for res in res_list:
            file_res.add_section(res)

        # Submit embedded files
        if len(new_files) > 0:
            new_files = sorted(list(set(new_files)))
            txt = f"Extracted from {'JAR'} file {filename}"
            for embed in new_files:
                request.add_extracted(embed, txt,
                                      embed.replace(extract_dir + "/", "").replace(decompiled_dir + "/", ""))

        if len(supplementary_files) > 0:
            supplementary_files = sorted(list(set(supplementary_files)))
            for original, decompiled in supplementary_files:
                txt = f"Decompiled {original.replace(extract_dir + '/', '').replace(decompiled_dir + '/', '')}"
                request.add_supplementary(decompiled, txt,
                                          decompiled.replace(extract_dir + "/", "").replace(decompiled_dir + "/", ""))

    def recurse_add_res(self, file_res, res_list, new_files, parent=None):
        for res_dic in res_list:
            # Check if condition is OK
            if self.pass_condition(res_dic.get("condition", None)):
                res = ResultSection(res_dic['title_text'],
                                    classification=res_dic.get('classification', Classification.UNRESTRICTED),
                                    parent=parent, body_format=res_dic.get('body_format', None))
                heur_id = self.heuristic_alteration(res_dic.get('score_condition', None), res_dic['heur_id'])
                res.set_heuristic(heur_id)

                # Add Tags
                tags = res_dic.get('tags', [])
                for res_tag in tags:
                    res.add_tag(res_tag[0], res_tag[1])

                # Add body
                body = res_dic.get('body', None)
                if body:
                    res.body = body

                # File for resubmit
                files = res_dic.get('files', [])
                for res_file in files:
                    if isinstance(res_file, tuple):
                        res_file = res_file[1]
                    new_files.append(res_file)

                # Recurse on children
                self.recurse_add_res(file_res, res_dic["children"], new_files, res)

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
