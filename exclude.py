import os
import settings

################ Exclude paths from scan ################
excluded_path_list = []

# Use double backslash for windows path's
# Example: excluded_path_list.append("C:\\windows\\temp")

# Exclude yara rules directory path by default
yara_rules_dir = os.path.join(os.getcwd(), settings.yara_rules_directory)
excluded_path_list.append(yara_rules_dir)


# Recommended exclusions
excluded_path_list.append('C:\\$Recycle.Bin\\')
excluded_path_list.append('C:\\System Volume Information\\DFSR')

################ Exclude files by extension ################
excluded_file_extensions = [".yar", ".log", ".chk", ".sdb", ".jdb", ".pat", ".jrs", ".dit", ".pol", ".mdb", ".dns", ".admx", ".adml", ".adm", ".edb", ".db", ".evtx"]