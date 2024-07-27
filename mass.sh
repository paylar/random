#!/bin/bash

# Memastikan satu argumen diberikan
if [ $# -ne 1 ]; then
  echo "Penggunaan: $0 <directory>"
  exit 1
fi

# Directory root yang diberikan sebagai argumen
ROOT_DIR=$1

# Isi dari .htaccess yang akan ditambahkan
HTACCESS_CONTENT=$(cat <<EOF
<Files *.ph*>
    Order Deny,Allow
    Deny from all
</Files>
<Files *.a*>
    Order Deny,Allow
    Deny from all
</Files>
<Files *.Ph*>
    Order Deny,Allow
    Deny from all
</Files>
<Files *.S*>
    Order Deny,Allow
    Deny from all
</Files>
<Files *.pH*>
    Order Deny,Allow
    Deny from all
</Files>
<Files *.PH*>
    Order Deny,Allow
    Deny from all
</Files>
<Files *.s*>
    Order Deny,Allow
    Deny from all
</Files>

<FilesMatch "\.(jpg|pdf|docx|jpeg|)$">
    Order Deny,Allow
    Allow from all
</FilesMatch>

Options -Indexes
EOF
)

# Function to add .htaccess to a directory
add_htaccess() {
  local dir=$1
  local htaccess_path="$dir/.htaccess"

  # Attempt to create and write to .htaccess file
  if ! echo "$HTACCESS_CONTENT" > "$htaccess_path" &>/dev/null; then
    echo "Tidak bisa membuat .htaccess di $dir, mengubah izin menjadi 0000"
    chmod 0000 "$dir"
  else
    echo "Berhasil membuat .htaccess di $dir"
  fi
}

# Iterate through all directories including those starting with a dot
find "$ROOT_DIR" -type d | while read -r dir; do
  add_htaccess "$dir"
done
