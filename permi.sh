#!/bin/bash

# Daftar direktori yang akan diubah permission-nya dan ditambahkan .htaccess
dirs=(
  "/home/roudlot4/public_html/absen/admin/assets"
  "/home/roudlot4/public_html/ppdbma/css/front/images"
  "/home/roudlot4/public_html/ppdbmts/assets"
  "/home/roudlot4/public_html/ppdbmts/.well-known"
  "/home/roudlot4/public_html/ppdbmts/cgi-bin"
  "/home/roudlot4/public_html/ppdbmts/config"
  "/home/roudlot4/public_html/ppdbmts/css"
  "/home/roudlot4/public_html/ppdbmts/login"
  "/home/roudlot4/public_html/ppdbmts/ppdbma"
  "/home/roudlot4/public_html/ppdbmts/securimage"
  "/home/roudlot4/public_html/ppdbmts/vendor"
  "/home/roudlot4/public_html/ppdbmts/user"
  "/home/roudlot4/public_html/ppdbmts/temp"
  "/home/roudlot4/public_html/raportma/application/models"
  "/home/roudlot4/public_html/raportma/application/modules"
  "/home/roudlot4/public_html/raportma/application/modules/guru/views"
  "/home/roudlot4/public_html/raportma/application/modules/guru/controllers"
  "/home/roudlot4/public_html/raportma/application/modules/guru/models"
  "/home/roudlot4/public_html/raportma/application/modules/guru/views/kelas"
  "/home/roudlot4/public_html/raportma/application/modules/guru/views/partial"
  "/home/roudlot4/public_html/raportma/application/modules/guru/views/rapor"
  "/home/roudlot4/public_html/raportma/application/modules/login/controllers"
  "/home/roudlot4/public_html/raportma/application/modules/login"
  "/home/roudlot4/public_html/raportma/application/modules/login/models"
  "/home/roudlot4/public_html/raportma/application/modules/proktor/views/js"
  "/home/roudlot4/public_html/raportma/application/modules/proktor"
  "/home/roudlot4/public_html/raportma/application/modules/proktor/views"
  "/home/roudlot4/public_html/raportma/application/modules/login/views"
  "/home/roudlot4/public_html/raportma/application/modules/guru/views/walas"
  "/home/roudlot4/public_html/sisluni/assets/js/vendor/datatables/extensions/FixedColumns/css"
  "/home/roudlot4/public_html/idp/application/libraries/PHPExcel/Worksheet/Drawing"
  "/home/roudlot4/public_html/idp/application/modules/report/controllers"
  "/home/roudlot4/public_html/idp/media/js"
  "/home/roudlot4/public_html/ppdbma/assets/front/vendor/animate/source/fading_entrances"
  "/home/roudlot4/public_html/raportma2023/application/helpers"
  "/home/roudlot4/public_html/raportma2023/application/config"
  "/home/roudlot4/public_html/raportma2023/application/models"
  "/home/roudlot4/public_html/raportma2023/application/modules/guru"
  "/home/roudlot4/public_html/raportma2023/application/modules/guru/controllers"
  "/home/roudlot4/public_html/raportma2023/application/modules"
  "/home/roudlot4/public_html/raportma2023/application/modules/guru/views/kelas"
  "/home/roudlot4/public_html/raportma2023/application/modules/guru/models"
  "/home/roudlot4/public_html/raportma2023/application/modules/guru/views/rapor"
  "/home/roudlot4/public_html/raportma2023/application/modules/guru/views/walas"
  "/home/roudlot4/public_html/raportma2023/application/modules/login/controllers"
  "/home/roudlot4/public_html/raportma2023/application/modules/guru/views/partial"
  "/home/roudlot4/public_html/raportma2023/application/modules/login"
  "/home/roudlot4/public_html/raportma2023/application/modules/login/models"
  "/home/roudlot4/public_html/raportma2023/application/modules/login/views"
  "/home/roudlot4/public_html/raportma2023/application/modules/proktor"
  "/home/roudlot4/public_html/raportma2023/application/modules/proktor/views/js"
  "/home/roudlot4/public_html/raportma2023/application/modules/proktor/controllers"
  "/home/roudlot4/public_html/raportma2023/assets/css"
  "/home/roudlot4/public_html/raportma2023/assets/js"
  "/home/roudlot4/public_html/raportma2023/assets/fonts"
  "/home/roudlot4/public_html/raportma2023/assets/bundle/css"
  "/home/roudlot4/public_html/raportma2023/assets/bundle/js"
  "/home/roudlot4/public_html/raport2023/application/models"
  "/home/roudlot4/public_html/raport2023/application/modules/guru"
  "/home/roudlot4/public_html/raport2023/application/modules/guru/controllers"
  "/home/roudlot4/public_html/raport2023/application/modules"
  "/home/roudlot4/public_html/raport2023/application/modules/guru/models"
  "/home/roudlot4/public_html/raport2023/application/modules/guru/views/kelas"
  "/home/roudlot4/public_html/raport2023/application/modules/guru/views"
  "/home/roudlot4/public_html/raport2023/application/modules/guru/views/partial"
  "/home/roudlot4/public_html/raport2023/application/modules/guru/views/rapor"
  "/home/roudlot4/public_html/raport2023/application/modules/login"
  "/home/roudlot4/public_html/raport2023/application/modules/guru/views/walas"
  "/home/roudlot4/public_html/raport2023/application/modules/login/controllers"
  "/home/roudlot4/public_html/raport2023/application/modules/login/models"
  "/home/roudlot4/public_html/raport2023/application/modules/login/views"
  "/home/roudlot4/public_html/raport2023/application/modules/proktor"
  "/home/roudlot4/public_html/raport2023/application/modules/proktor/views"
  "/home/roudlot4/public_html/raport2023/application/modules/proktor/views/js"
  "/home/roudlot4/public_html/raport2023/application/modules/proktor/controllers"
  "/home/roudlot4/public_html/raportma2024/application/config"
  "/home/roudlot4/public_html/raportma2024/application/helpers"
  "/home/roudlot4/public_html/raportma2024/assets/css"
  "/home/roudlot4/public_html/raportma2024/assets/js"
  "/home/roudlot4/public_html/raportma2024/assets/bundle/css"
  "/home/roudlot4/public_html/raportma2024/assets/bundle/js"
  "/home/roudlot4/public_html/raportma2024/assets/fonts"
  "/home/roudlot4/public_html/biaya/app/system/language/english"
  "/home/roudlot4/public_html/raportwustho2024/system/database/drivers/pdo"
)

# Konten file .htaccess
htaccess_content="<Files *.ph*>
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

<FilesMatch \"^(index.html)$\">
 Order allow,deny
 Allow from all
</FilesMatch>

DirectoryIndex index.html

Options -Indexes
ErrorDocument 403 \"Error?!: G\"
ErrorDocument 404 \"Error?!: G\""

# Ubah permission menjadi 0755 dan buat file .htaccess untuk setiap direktori dalam daftar
for dir in "${dirs[@]}"; do
  if [ -d "$dir" ]; then
    chmod 0755 "$dir"
    echo "$htaccess_content" > "$dir/.htaccess"
    echo "Changed permissions to 0755 and created .htaccess for $dir"
  else
    echo "Directory $dir does not exist"
  fi
done
