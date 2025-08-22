<?php
ini_set('session.cookie_lifetime', 250600); // 3600 segundos = 1 hora
session_start();

// Configuración de sesiones seguras
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 1 : 0);
ini_set('session.use_strict_mode', 1);
ini_set('session.cookie_samesite', 'Strict');

// Configuración de seguridad
ini_set('display_errors', 0); // Cambiar a 1 temporalmente para depuración si es necesario
error_reporting(E_ALL);

// Configuración
$contentDir = 'content' . DIRECTORY_SEPARATOR;
$allowedExtensions = ['txt', 'md', 'json'];
$maxFileSize = 2 * 1024 * 1024; // 2MB máximo
$maxRemoteSize = 1 * 1024 * 1024; // 1MB máximo para contenido remoto

// Lista de dominios bloqueados
$blockedDomains = [
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
    '10.',
    '172.',
    '192.168.',
    'file://',
    'ftp://',
    'data:',
    'javascript:',
    'php://'
];

// Función para validar y sanitizar nombres de archivo, permitiendo subdirectorios
function validateAndSanitizeFilename($filename) {
    $filename = urldecode($filename);
    // Normalizar separadores de directorio
    $filename = str_replace('\\', '/', $filename);
    // Eliminar patrones peligrosos
    $dangerous = ['../', '..\\', './', '.\\', '//', 'php://', 'file://', 'data:', 'http:', 'https:', 'ftp:'];
    foreach ($dangerous as $pattern) {
        if (stripos($filename, $pattern) !== false) {
            error_log("Patrón peligroso detectado en archivo: $filename");
            return false;
        }
    }
    // Sanitizar componentes del path
    $parts = explode('/', $filename);
    $sanitizedParts = [];
    foreach ($parts as $part) {
        $part = preg_replace('/[^a-zA-Z0-9._-]/', '', $part);
        if (empty($part) || strlen($part) > 255) {
            error_log("Componente de archivo inválido: $part");
            return false;
        }
        $sanitizedParts[] = $part;
    }
    $sanitizedFilename = implode('/', $sanitizedParts);
    if (empty($sanitizedFilename)) {
        error_log("Nombre de archivo inválido después de sanitización: $filename");
        return false;
    }
    return $sanitizedFilename;
}

// Función para verificar si el archivo está dentro del directorio permitido
function isFileInAllowedDirectory($filepath, $allowedDir) {
    $realFilepath = realpath($filepath);
    $realAllowedDir = realpath($allowedDir);
    if ($realFilepath === false || $realAllowedDir === false) {
        error_log("Ruta inválida - Archivo: $filepath, Directorio: $allowedDir");
        return false;
    }
    return strpos($realFilepath, $realAllowedDir) === 0;
}

// Función para detectar código PHP peligroso en el contenido
function containsPHPCode($content, $type) {
    if ($type === 'txt') {
        return false;
    }
    $contentToCheck = preg_replace('/```[\s\S]*?```/', '', $content);
    $contentToCheck = preg_replace('/`[^`]*`/', '', $contentToCheck);
    $contentToCheck = preg_replace('/^\s{4,}.*$/m', '', $contentToCheck);
    $dangerousPHPPatterns = [
        '/<\?php\s+\w+/i',
        '/<\?=/i',
        '/\b(eval|exec|system|shell_exec|passthru|call_user_func|create_function)\s*\(/i',
        '/\b(file_get_contents|file_put_contents|fopen|fwrite|include|require|include_once|require_once)\s*\(/i',
        '/\$_[A-Z]+\[\s*[\'"]\w+[\'"]\s*\]/i',
        '/\bpreg_replace\s*\(.*\/e\)/i',
    ];
    foreach ($dangerousPHPPatterns as $pattern) {
        if (preg_match($pattern, $contentToCheck)) {
            error_log("Código PHP peligroso detectado: " . substr($contentToCheck, 0, 100));
            return true;
        }
    }
    $injectionPatterns = [
        '/\?\>\s*<\?php/i',
        '/<\?php.*?echo.*?\$_/i',
        '/<\?php.*?print.*?\$_/i',
    ];
    foreach ($injectionPatterns as $pattern) {
        if (preg_match($pattern, $contentToCheck)) {
            return true;
        }
    }
    return false;
}

// Función para sanitizar contenido
function sanitizeContent($content, $type) {
    if (containsPHPCode($content, $type)) {
        return ['error' => 'Contenido bloqueado: se detectó código potencialmente peligroso'];
    }
    global $maxRemoteSize;
    if (strlen($content) > $maxRemoteSize) {
        return ['error' => 'Contenido demasiado grande (máximo ' . ($maxRemoteSize / 1024) . 'KB)'];
    }
    if ($type === 'html' || stripos($content, '<script') !== false || stripos($content, 'javascript:') !== false) {
        return ['error' => 'Tipo de contenido no permitido'];
    }
    return ['content' => $content];
}

// Función para verificar si un dominio está bloqueado
function isDomainBlocked($url) {
    global $blockedDomains;
    $parsedUrl = parse_url(strtolower($url));
    if (!$parsedUrl) {
        return true;
    }
    $host = $parsedUrl['host'] ?? '';
    foreach ($blockedDomains as $blocked) {
        if (strpos($host, $blocked) === 0) {
            return true;
        }
    }
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        if (!filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
            return true;
        }
    }
    return false;
}

// Función para obtener contenido de URL remota con medidas de seguridad
function getRemoteContent($url) {
    if (!filter_var($url, FILTER_VALIDATE_URL) || parse_url($url, PHP_URL_SCHEME) !== 'https') {
        return ['error' => 'URL no válida o no es HTTPS'];
    }
    if (isDomainBlocked($url)) {
        return ['error' => 'Dominio no permitido por políticas de seguridad'];
    }
    $context = stream_context_create([
        'http' => [
            'method' => 'GET',
            'timeout' => 15,
            'user_agent' => 'VisorWeb/1.0 (Tutorial Viewer)',
            'follow_location' => false,
            'max_redirects' => 0,
            'ignore_errors' => true
        ],
        'ssl' => [
            'verify_peer' => true,
            'verify_peer_name' => true,
            'allow_self_signed' => false
        ]
    ]);
    $content = @file_get_contents($url, false, $context);
    if ($content === false) {
        $error = error_get_last()['message'] ?? 'Error desconocido';
        error_log("Error al obtener URL $url: $error");
        return ['error' => 'No se pudo acceder a la URL: ' . $error];
    }
    $sanitized = sanitizeContent($content, 'remote');
    if (isset($sanitized['error'])) {
        return $sanitized;
    }
    $extension = strtolower(pathinfo(parse_url($url, PHP_URL_PATH), PATHINFO_EXTENSION));
    if (empty($extension)) {
        $trimmedContent = trim($content);
        if (strpos($trimmedContent, '# ') === 0 || strpos($trimmedContent, '## ') !== false) {
            $extension = 'md';
        } elseif (json_decode($trimmedContent) !== null && json_last_error() === JSON_ERROR_NONE) {
            $extension = 'json';
        } else {
            $extension = 'txt';
        }
    }
    global $allowedExtensions;
    if (!in_array($extension, $allowedExtensions)) {
        $extension = 'txt';
    }
    return [
        'content' => $sanitized['content'],
        'type' => $extension,
        'url' => htmlspecialchars($url, ENT_QUOTES, 'UTF-8')
    ];
}

// Función para obtener todos los archivos y carpetas con validación de seguridad
function getContentFiles($dir, $extensions) {
    $result = ['root' => [], 'folders' => []];
    $realDir = realpath($dir);
    if (!$realDir || !is_dir($realDir)) {
        error_log("Directorio $dir no existe o no accesible");
        return $result;
    }
    global $maxFileSize;

    // Escanear directorios y archivos
    $items = scandir($realDir);
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') {
            continue;
        }
        $itemPath = $realDir . DIRECTORY_SEPARATOR . $item;
        if (is_dir($itemPath)) {
            // Procesar subdirectorio
            $folderFiles = [];
            foreach ($extensions as $ext) {
                foreach (glob($itemPath . DIRECTORY_SEPARATOR . '*.' . $ext) as $fullPath) {
                    if (!is_file($fullPath) || filesize($fullPath) > $maxFileSize) {
                        continue;
                    }
                    $file = basename($fullPath);
                    $sanitizedFile = validateAndSanitizeFilename($file);
                    if ($sanitizedFile) {
                        $relativePath = $item . '/' . $sanitizedFile;
                        $folderFiles[] = [
                            'name' => $relativePath,
                            'title' => ucfirst(str_replace(['_', '-'], ' ', pathinfo($sanitizedFile, PATHINFO_FILENAME))),
                            'path' => $fullPath,
                            'type' => $ext
                        ];
                    }
                }
            }
            if (!empty($folderFiles)) {
                $result['folders'][$item] = [
                    'name' => $item,
                    'title' => ucfirst(str_replace(['_', '-'], ' ', $item)),
                    'files' => $folderFiles
                ];
            }
        } elseif (is_file($itemPath)) {
            // Procesar archivos en el directorio raíz
            $ext = strtolower(pathinfo($itemPath, PATHINFO_EXTENSION));
            if (!in_array($ext, $extensions) || filesize($itemPath) > $maxFileSize) {
                continue;
            }
            $file = basename($itemPath);
            $sanitizedFile = validateAndSanitizeFilename($file);
            if ($sanitizedFile) {
                $result['root'][] = [
                    'name' => $sanitizedFile,
                    'title' => ucfirst(str_replace(['_', '-'], ' ', pathinfo($sanitizedFile, PATHINFO_FILENAME))),
                    'path' => $itemPath,
                    'type' => $ext
                ];
            }
        }
    }
    return $result;
}

// Función para obtener hasta 6 archivos relacionados de la misma carpeta, seleccionados aleatoriamente
function getRelatedFiles($selectedFile, $files) {
    $related = [];
    $selectedFolder = '';
    
    // Determinar la carpeta del archivo seleccionado
    if ($selectedFile && strpos($selectedFile, '/') !== false) {
        $parts = explode('/', $selectedFile);
        $selectedFolder = $parts[0];
        $selectedFileName = $parts[1];
    } else {
        $selectedFileName = $selectedFile;
    }
    
    // Obtener archivos de la carpeta correspondiente
    if ($selectedFolder && isset($files['folders'][$selectedFolder])) {
        $related = $files['folders'][$selectedFolder]['files'];
    } else {
        $related = $files['root'];
    }
    
    // Excluir el archivo seleccionado
    $related = array_filter($related, function($file) use ($selectedFile) {
        return $file['name'] !== $selectedFile;
    });
    
    // Seleccionar hasta 6 archivos aleatorios
    if (!empty($related)) {
        $keys = array_keys($related);
        $numToSelect = min(6, count($keys));
        $randomKeys = $numToSelect > 0 ? array_rand($keys, $numToSelect) : [];
        $randomKeys = (array)$randomKeys; // Convertir a array si es un solo elemento
        $selectedFiles = [];
        foreach ($randomKeys as $key) {
            $selectedFiles[] = $related[$keys[$key]];
        }
        $related = $selectedFiles;
    }
    
    // Generar HTML para la lista de temas relacionados
    if (empty($related)) {
        return '';
    }
    
    $html = '<hr style="border: none; height: 2px; background-color: #36444e; margin: 20px 0;">';
    $html .= '<div class="related-topics">';
    $html .= '<h2>Ver otros temas:</h2>';
    $html .= '<ul class="related-list">';
    foreach ($related as $file) {
        $html .= '<li>';
        $html .= '<a href="?file=' . urlencode($file['name']) . '" class="related-link">';
        $html .= htmlspecialchars($file['title'], ENT_QUOTES, 'UTF-8') . ' <span class="file-type">.' . htmlspecialchars($file['type'], ENT_QUOTES, 'UTF-8') . '</span>';
        $html .= '</a>';
        $html .= '</li>';
    }
    $html .= '</ul>';
    $html .= '</div>';
    
    return $html;
}

// Función para procesar contenido según el tipo con validación de seguridad
function processContent($filePath, $type, $selectedFile, $files) {
    global $contentDir, $maxFileSize;
    if (!isFileInAllowedDirectory($filePath, $contentDir)) {
        return '<div class="error">Error de seguridad: Acceso a archivo no autorizado</div>';
    }
    if (!file_exists($filePath) || !is_readable($filePath)) {
        return '<div class="error">Error: No se puede leer el archivo</div>';
    }
    if (filesize($filePath) > $maxFileSize) {
        return '<div class="error">Error: Archivo demasiado grande (máximo ' . ($maxFileSize / 1024 / 1024) . 'MB)</div>';
    }
    $content = file_get_contents($filePath);
    if ($content === false) {
        return '<div class="error">Error: No se pudo leer el contenido del archivo</div>';
    }
    $sanitized = sanitizeContent($content, $type);
    if (isset($sanitized['error'])) {
        return '<div class="error">' . htmlspecialchars($sanitized['error'], ENT_QUOTES, 'UTF-8') . '</div>';
    }
    $processedContent = processContentDirect($sanitized['content'], $type);
    // Agregar temas relacionados solo para archivos locales
    $relatedContent = getRelatedFiles($selectedFile, $files);
    return $processedContent . $relatedContent;
}

// Función para procesar contenido remoto con validación
function processRemoteContent($content, $type) {
    return processContentDirect($content, $type);
}

// Función para procesar contenido directo (sin archivo) con escape HTML
function processContentDirect($content, $type) {
    switch ($type) {
        case 'json':
            $data = json_decode($content, true);
            if (json_last_error() === JSON_ERROR_NONE) {
                return formatJsonContent($data);
            }
            return '<div class="error">Error al procesar contenido JSON</div>';
        case 'md':
            return formatMarkdownContent($content);
        case 'txt':
        default:
            return formatTextContent($content);
    }
}

// Formatear contenido JSON con escape de HTML
function formatJsonContent($data) {
    $html = '<div class="json-content">';
    if (isset($data['title'])) {
        $html .= '<h1>' . htmlspecialchars($data['title'], ENT_QUOTES, 'UTF-8') . '</h1>';
    }
    if (isset($data['description'])) {
        $html .= '<p class="description">' . htmlspecialchars($data['description'], ENT_QUOTES, 'UTF-8') . '</p>';
    }
    if (isset($data['sections']) && is_array($data['sections'])) {
        foreach ($data['sections'] as $section) {
            if (isset($section['title'])) {
                $html .= '<h2>' . htmlspecialchars($section['title'], ENT_QUOTES, 'UTF-8') . '</h2>';
            }
            if (isset($section['content'])) {
                $html .= '<p>' . nl2br(htmlspecialchars($section['content'], ENT_QUOTES, 'UTF-8')) . '</p>';
            }
        }
    } else {
        $html .= '<pre class="json-display">' . htmlspecialchars(json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), ENT_QUOTES, 'UTF-8') . '</pre>';
    }
    $html .= '</div>';
    return $html;
}

// Función para procesar contenido inline (enlaces, negritas, cursivas, código en línea)
function processInlineMarkdown($content) {
    // Procesar enlaces
    $content = preg_replace_callback(
        '/\[([^\]]+)\]\(([^)\s]+)(?:\s+"([^"]+)")?\)/',
        function($matches) {
            $text = $matches[1];
            $url = $matches[2];
            $title = isset($matches[3]) ? $matches[3] : '';
            if (filter_var($url, FILTER_VALIDATE_URL) && (strpos($url, 'http://') === 0 || strpos($url, 'https://') === 0)) {
                $titleAttr = $title ? ' title="' . htmlspecialchars($title, ENT_QUOTES, 'UTF-8') . '"' : '';
                return '<a href="' . htmlspecialchars($url, ENT_QUOTES, 'UTF-8') . '"' . $titleAttr . ' target="_blank" rel="noopener noreferrer">' . htmlspecialchars($text, ENT_QUOTES, 'UTF-8') . '</a>';
            } else {
                return htmlspecialchars($text, ENT_QUOTES, 'UTF-8') . ' (' . htmlspecialchars($url, ENT_QUOTES, 'UTF-8') . ($title ? ' "' . htmlspecialchars($title, ENT_QUOTES, 'UTF-8') . '"' : '') . ')';
            }
        },
        $content
    );
    
    // Procesar código en línea
    $content = preg_replace('/`([^`]+)`/', '<code class="inline-code">' . htmlspecialchars('$1', ENT_QUOTES, 'UTF-8') . '</code>', $content);
    
    // Procesar tachado
    $content = preg_replace('/~~(.+?)~~/', '<del>' . htmlspecialchars('$1', ENT_QUOTES, 'UTF-8') . '</del>', $content);
    
    // Procesar negritas
    $content = preg_replace('/\*\*([^\*<>]*?)\*\*/', '<strong>' . htmlspecialchars('$1', ENT_QUOTES, 'UTF-8') . '</strong>', $content);
    
    // Procesar cursivas
    $content = preg_replace('/\*([^\*<>]*?)\*/', '<em>' . htmlspecialchars('$1', ENT_QUOTES, 'UTF-8') . '</em>', $content);
    
    return $content;
}

// Función para formatear contenido Markdown con escape HTML
function formatMarkdownContent($content) {
    // Mapa de nombres de lenguajes para mensajes personalizados
    $languageNames = [
        'php' => 'PHP',
        'python' => 'Python',
        'css' => 'CSS',
        'javascript' => 'JavaScript',
        'html' => 'HTML',
        'json' => 'JSON',
        '' => 'Código'
    ];
    
    // Procesar bloques de código primero (sin escapar el contenido del código)
    $codeBlocks = [];
    $content = preg_replace_callback(
        '/```(\w*)\n(.*?)\n```/s',
        function ($matches) use ($languageNames, &$codeBlocks) {
            $language = strtolower($matches[1]);
            $codeContent = $matches[2];
            $languageLabel = isset($languageNames[$language]) ? $languageNames[$language] : $languageNames[''];
            $placeholder = '__CODE_BLOCK_' . count($codeBlocks) . '__';
            $codeBlocks[$placeholder] = '<pre class="code-block language-' . htmlspecialchars($language, ENT_QUOTES, 'UTF-8') . '"><div class="code-label">Código ' . htmlspecialchars($languageLabel, ENT_QUOTES, 'UTF-8') . '</div><code>' . htmlspecialchars($codeContent, ENT_QUOTES, 'UTF-8') . '</code></pre>';
            return $placeholder;
        },
        $content
    );
    
    // Procesar líneas horizontales
    $content = preg_replace('/^---$/m', '<hr style="border: none; height: 2px; background-color: #36444e; margin: 10px 0;">', $content);
    
    // Procesar tablas Markdown
    $content = preg_replace_callback(
        '/^\|(.+?)\|\n\|([-|: ]+)\|\n((?:\|.*\|\n)*)/m',
        function ($matches) {
            $headers = array_map('trim', explode('|', trim($matches[1], '|')));
            $html = '<table class="markdown-table">';
            $html .= '<thead><tr>';
            foreach ($headers as $header) {
                $html .= '<th>' . htmlspecialchars(trim($header), ENT_QUOTES, 'UTF-8') . '</th>';
            }
            $html .= '</tr></thead>';
            $html .= '<tbody>';
            $rows = explode("\n", trim($matches[3]));
            foreach ($rows as $row) {
                if (trim($row) === '') continue;
                $cells = array_map('trim', explode('|', trim($row, '|')));
                $html .= '<tr>';
                foreach ($cells as $cell) {
                    $html .= '<td>' . htmlspecialchars(trim($cell), ENT_QUOTES, 'UTF-8') . '</td>';
                }
                $html .= '</tr>';
            }
            $html .= '</tbody></table>';
            return $html;
        },
        $content
    );
    
    // Procesar encabezados
    $content = preg_replace('/^###### (.*)$/m', '<h6>' . htmlspecialchars('$1', ENT_QUOTES, 'UTF-8') . '</h6>', $content);
    $content = preg_replace('/^##### (.*)$/m', '<h5>' . htmlspecialchars('$1', ENT_QUOTES, 'UTF-8') . '</h5>', $content);
    $content = preg_replace('/^#### (.*)$/m', '<h4>' . htmlspecialchars('$1', ENT_QUOTES, 'UTF-8') . '</h4>', $content);
    $content = preg_replace('/^### (.*)$/m', '<h3>' . htmlspecialchars('$1', ENT_QUOTES, 'UTF-8') . '</h3>', $content);
    $content = preg_replace('/^## (.*)$/m', '<h2>' . htmlspecialchars('$1', ENT_QUOTES, 'UTF-8') . '</h2>', $content);
    $content = preg_replace('/^# (.*)$/m', '<h1>' . htmlspecialchars('$1', ENT_QUOTES, 'UTF-8') . '</h1>', $content);

    // Imágenes Markdown ![alt](url "title")
    $content = preg_replace_callback(
        '/!\[([^\]]*)\]\(([^\s\)]+)(?:\s+"([^"]+)")?\)/',
        function ($matches) {
            $alt = htmlspecialchars($matches[1], ENT_QUOTES, 'UTF-8');
            $src = htmlspecialchars($matches[2], ENT_QUOTES, 'UTF-8');
            $title = isset($matches[3]) ? ' title="' . htmlspecialchars($matches[3], ENT_QUOTES, 'UTF-8') . '"' : '';
            return '<img src="' . $src . '" alt="' . $alt . '"' . $title . ' style="max-width:100%; height:auto;">';
        },
        $content
    );
    
    // Procesar listas (ordenadas y no ordenadas) con soporte para anidamiento
    $lines = explode("\n", $content);
    $processedLines = [];
    $listStack = []; // Pila para manejar anidamiento de listas
    $currentIndent = 0;
    $quoteStack = []; // Pila para citas (blockquote)
    $currentQuoteLevel = 0;
    
    foreach ($lines as $line) {
        $trimmedLine = trim($line);
        if (empty($trimmedLine)) {
            if (!empty($listStack)) {
                while (!empty($listStack)) {
                    $processedLines[] = array_pop($listStack);
                }
                $currentIndent = 0;
            }
            if (!empty($quoteStack)) {
                while (!empty($quoteStack)) {
                    $processedLines[] = array_pop($quoteStack);
                }
                $currentQuoteLevel = 0;
            }
            $processedLines[] = '';
            continue;
        }
        
        // Procesar citas (blockquote con soporte para anidamiento)
        if (preg_match('/^\s*((?:>\s*)+)\s?(.*)$/', $line, $qmatches)) {
            preg_match_all('/>/', $qmatches[1], $m);
            $quoteLevel = count($m[0]);
            $quoteContent = $qmatches[2];
            
            while ($currentQuoteLevel < $quoteLevel) {
                $processedLines[] = '<blockquote>';
                array_push($quoteStack, '</blockquote>');
                $currentQuoteLevel++;
            }
            while ($currentQuoteLevel > $quoteLevel) {
                $processedLines[] = array_pop($quoteStack);
                $currentQuoteLevel--;
            }
            
            if (trim($quoteContent) === '') {
                $processedLines[] = '';
            } else {
                $processedLines[] = processInlineMarkdown($quoteContent);
            }
            continue;
        }
        
        // Contar espacios de indentación
        preg_match('/^(\s*)/', $line, $indentMatch);
        $indentLevel = strlen($indentMatch[1]) / 2;
        
        // Procesar listas ordenadas
        if (preg_match('/^(\s*)(\d+)\.\s+(.*)$/', $line, $matches) && !empty($matches[3])) {
            $itemContent = $matches[3];
            $itemIndent = strlen($matches[1]) / 2;
            
            while ($itemIndent < $currentIndent) {
                $processedLines[] = array_pop($listStack);
                $currentIndent--;
            }
            if ($itemIndent > $currentIndent) {
                $processedLines[] = '<ol>';
                array_push($listStack, '</ol>');
                $currentIndent = $itemIndent;
            } elseif ($itemIndent == 0 && empty($listStack)) {
                $processedLines[] = '<ol>';
                array_push($listStack, '</ol>');
                $currentIndent = 0;
            }
            
            $itemContent = processInlineMarkdown($itemContent);
            $processedLines[] = "<li>$itemContent</li>";
        }
        // Procesar listas no ordenadas
        elseif (preg_match('/^(\s*)- (.*)$/', $line, $matches) && !empty($matches[2])) {
            $itemContent = $matches[2];
            $itemIndent = strlen($matches[1]) / 2;
            
            while ($itemIndent < $currentIndent) {
                $processedLines[] = array_pop($listStack);
                $currentIndent--;
            }
            if ($itemIndent > $currentIndent) {
                $processedLines[] = '<ul>';
                array_push($listStack, '</ul>');
                $currentIndent = $itemIndent;
            } elseif ($itemIndent == 0 && empty($listStack)) {
                $processedLines[] = '<ul>';
                array_push($listStack, '</ul>');
                $currentIndent = 0;
            }
            
            $itemContent = processInlineMarkdown($itemContent);
            $processedLines[] = "<li>$itemContent</li>";
        }
        // Línea normal
        else {
            if ($currentQuoteLevel > 0) {
                while ($currentQuoteLevel > 0) {
                    $processedLines[] = array_pop($quoteStack);
                    $currentQuoteLevel--;
                }
            }
            if (!empty($listStack)) {
                while (!empty($listStack)) {
                    $processedLines[] = array_pop($listStack);
                }
                $currentIndent = 0;
            }
            $processedLines[] = processInlineMarkdown($line);
        }
    }
    
    while (!empty($listStack)) {
        $processedLines[] = array_pop($listStack);
    }
    while (!empty($quoteStack)) {
        $processedLines[] = array_pop($quoteStack);
    }
    
    for ($i = 0; $i < count($processedLines); $i++) {
        foreach ($codeBlocks as $placeholder => $codeBlock) {
            $processedLines[$i] = str_replace($placeholder, $codeBlock, $processedLines[$i]);
        }
    }
    
    $content = implode("\n", $processedLines);
    $content = '<p>' . $content . '</p>';
    $content = preg_replace('/<p>\s*<\/p>/', '', $content);
    $content = preg_replace('/<p>\s*(<h[1-6]>)/', '$1', $content);
    $content = preg_replace('/(<\/h[1-6]>)\s*<\/p>/', '$1', $content);
    $content = preg_replace('/<p>\s*(<ul>)/', '$1', $content);
    $content = preg_replace('/(<\/ul>)\s*<\/p>/', '$1', $content);
    $content = preg_replace('/<p>\s*(<ol>)/', '$1', $content);
    $content = preg_replace('/(<\/ol>)\s*<\/p>/', '$1', $content);
    $content = preg_replace('/<p>\s*(<pre)/', '$1', $content);
    $content = preg_replace('/(<\/pre>)\s*<\/p>/', '$1', $content);
    $content = preg_replace('/<p>\s*(<table)/', '$1', $content);
    $content = preg_replace('/(<\/table>)\s*<\/p>/', '$1', $content);
    $content = preg_replace('/<p>\s*(<hr>)/', '$1', $content);
    $content = preg_replace('/<p>\s*(<blockquote>)/', '$1', $content);
    $content = preg_replace('/(<\/blockquote>)\s*<\/p>/', '$1', $content);
    
    $content = preg_replace_callback('/<p>(.*?)<\/p>/s', function($matches) {
        $paragraphContent = $matches[1];
        if (!preg_match('/<(h[1-6]|ul|ol|li|pre|code|table|hr|a|blockquote)/i', $paragraphContent)) {
            $paragraphContent = htmlspecialchars($paragraphContent, ENT_QUOTES, 'UTF-8');
            $paragraphContent = str_replace("\n", '<br>', $paragraphContent);
        }
        return '<p>' . $paragraphContent . '</p>';
    }, $content);
    
    return '<div class="markdown-content">' . $content . '</div>';
}

// Formatear contenido de texto con escape HTML
function formatTextContent($content) {
    $content = htmlspecialchars($content, ENT_QUOTES, 'UTF-8');
    $content = nl2br($content);
    return '<div class="text-content"><p>' . $content . '</p></div>';
}

// Obtener archivos y carpetas
$files = getContentFiles($contentDir, $allowedExtensions);

// Manejar URL remota con validación
$remoteUrl = filter_input(INPUT_GET, 'url', FILTER_SANITIZE_URL);
$remoteContent = null;
if (!empty($remoteUrl)) {
    $remoteContent = getRemoteContent($remoteUrl);
}

// Obtener archivo seleccionado con validación
$selectedFile = filter_input(INPUT_GET, 'file', FILTER_SANITIZE_STRING);
if ($selectedFile) {
    $selectedFile = validateAndSanitizeFilename($selectedFile);
}

$currentContent = '';
$currentTitle = 'Selecciona una guía temática';

// Priorizar contenido remoto si existe
if ($remoteContent && !isset($remoteContent['error'])) {
    $currentContent = processRemoteContent($remoteContent['content'], $remoteContent['type']);
    $currentTitle = 'Contenido Remoto: ' . basename($remoteContent['url']);
} elseif ($remoteContent && isset($remoteContent['error'])) {
    $currentContent = '<div class="error">Error: ' . htmlspecialchars($remoteContent['error'], ENT_QUOTES, 'UTF-8') . '</div>';
    $currentTitle = 'Error al cargar URL remota';
} elseif ($selectedFile) {
    $filePath = $contentDir . $selectedFile;
    if (file_exists($filePath) && isFileInAllowedDirectory($filePath, $contentDir)) {
        $currentContent = processContent($filePath, pathinfo($filePath, PATHINFO_EXTENSION), $selectedFile, $files);
        $currentTitle = ucfirst(str_replace(['_', '-'], ' ', pathinfo(basename($selectedFile), PATHINFO_FILENAME)));
    } else {
        $currentContent = '<div class="error">Error: El archivo seleccionado no existe o no es accesible</div>';
        $currentTitle = 'Archivo no encontrado';
    }
}

// Manejar cambio de tema con validación
$validThemes = ['light', 'dark'];
if (isset($_POST['theme']) && in_array($_POST['theme'], $validThemes)) {
    $_SESSION['theme'] = $_POST['theme'];
}
$currentTheme = $_SESSION['theme'] ?? 'light';
if (!in_array($currentTheme, $validThemes)) {
    $currentTheme = 'light';
}
?>

<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Guías Temáticas</title>
    <link rel="stylesheet" href="styles.css">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/github.min.css" integrity="sha512-M7XkQ7vY4O0Q3+H3p5G7nJk06vZpH4QHjvUuXk1eKQkXJ9v8gU7Hq4f8m2OeXxw2b6H4bZgWwEo1JbV+0f1ycA==" crossorigin="anonymous" referrerpolicy="no-referrer" />
    <script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js" integrity="sha512-fV2t2wY2r4mZx9Xq8JqBv3l5y2pXzJbHc0v8H4nqQ2qgqKx6L0qPjN3m4m4m9wTg0Jgk6gNn9y0WwP2m7m2xWA==" crossorigin="anonymous" referrerpolicy="no-referrer" defer></script>
    <style>
        .folder-title {
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin: 1rem 0 0.5rem 0;
            padding-left: 0.5rem;
            border-left: 3px solid var(--accent-primary);
        }
        .file-item.folder-file {
            padding-left: 1.5rem;
            border-left: 1px dashed var(--border-medium);
        }
        .related-topics {
            margin-top: 2rem;
        }
        .related-topics h2 {
            font-size: 1.5rem;
            margin-bottom: 1rem;
        }
        .related-list {
            list-style: none;
            padding: 0;
        }
        .related-list li {
            margin: 0.5rem 0;
        }
        .related-link {
            color: var(--accent-primary);
            text-decoration: none;
            font-size: 1rem;
        }
        .related-link:hover {
            text-decoration: underline;
        }
        .related-link .file-type {
            color: var(--text-secondary);
            font-size: 0.8rem;
        }
    </style>
</head>
<body class="<?php echo htmlspecialchars($currentTheme, ENT_QUOTES, 'UTF-8'); ?>-theme">
    <div class="container">
        <header class="header">
            <h1 class="logo">📚 Guías Temáticas</h1>
            <div class="header-controls">
                <form method="get" class="url-form" style="margin-right: 1rem;">
                    <input type="url" 
                           name="url" 
                           placeholder="Ingresa URL HTTPS..." 
                           value="<?php echo htmlspecialchars($remoteUrl ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                           class="url-input"
                           maxlength="2000"
                           pattern="https://.*"
                           title="Solo URLs HTTPS son permitidas"
                           style="padding: 0.5rem; border-radius: 6px; border: 1px solid var(--border-medium); background: var(--bg-primary); color: var(--text-primary); width: 300px;">
                    <button type="submit" class="url-btn" style="padding: 0.5rem 1rem; margin-left: 0.5rem; background: var(--accent-primary); color: white; border: none; border-radius: 6px; cursor: pointer;">
                        🌐 Cargar
                    </button>
                    <?php if (!empty($remoteUrl)): ?>
                        <a href="?" class="clear-btn" style="padding: 0.5rem; margin-left: 0.5rem; background: var(--error); color: white; text-decoration: none; border-radius: 6px; display: inline-block;">
                            ✕ Limpiar
                        </a>
                    <?php endif; ?>
                </form>
                <form method="post" class="theme-switcher">
                    <button type="submit" name="theme" value="<?php echo $currentTheme === 'light' ? 'dark' : 'light'; ?>" class="theme-btn">
                        <?php echo $currentTheme === 'light' ? '🌙' : '☀️'; ?>
                        <?php echo $currentTheme === 'light' ? 'Oscuro' : 'Claro'; ?>
                    </button>
                </form>
            </div>
        </header>

        <div class="main-layout">
            <aside class="sidebar">
                <h2 class="sidebar-title">📋 Lista de Temas</h2>
                <?php if (!empty($remoteUrl)): ?>
                    <div class="remote-indicator">
                        <p class="remote-label">🌐 Contenido Remoto Activo</p>
                        <p class="remote-url"><?php echo htmlspecialchars($remoteUrl, ENT_QUOTES, 'UTF-8'); ?></p>
                    </div>
                <?php endif; ?>
                <nav class="file-list">
                    <?php if (empty($files['root']) && empty($files['folders'])): ?>
                        <p class="no-files">No se encontraron archivos en el directorio 'content/'</p>
                    <?php else: ?>
                        <?php if (!empty($files['root'])): ?>
                            <div class="file-section">
                                <h4 class="folder-title">Archivos Principales</h4>
                                <?php foreach ($files['root'] as $file): ?>
                                    <a href="?file=<?php echo urlencode($file['name']); ?>" 
                                       class="file-item <?php echo ($selectedFile === $file['name'] && empty($remoteUrl)) ? 'active' : ''; ?>">
                                        <span class="file-icon">
                                            <?php 
                                            switch($file['type']) {
                                                case 'json': echo '📋'; break;
                                                case 'md': echo '📝'; break;
                                                case 'txt': echo '📄'; break;
                                                default: echo '📄';
                                            }
                                            ?>
                                        </span>
                                        <span class="file-title"><?php echo htmlspecialchars($file['title'], ENT_QUOTES, 'UTF-8'); ?></span>
                                        <span class="file-type">.<?php echo htmlspecialchars($file['type'], ENT_QUOTES, 'UTF-8'); ?></span>
                                    </a>
                                <?php endforeach; ?>
                            </div>
                        <?php endif; ?>
                        <?php foreach ($files['folders'] as $folder): ?>
                            <div class="file-section">
                                <h4 class="folder-title"><?php echo htmlspecialchars($folder['title'], ENT_QUOTES, 'UTF-8'); ?></h4>
                                <?php foreach ($folder['files'] as $file): ?>
                                    <a href="?file=<?php echo urlencode($file['name']); ?>" 
                                       class="file-item folder-file <?php echo ($selectedFile === $file['name'] && empty($remoteUrl)) ? 'active' : ''; ?>">
                                        <span class="file-icon">
                                            <?php 
                                            switch($file['type']) {
                                                case 'json': echo '📋'; break;
                                                case 'md': echo '📝'; break;
                                                case 'txt': echo '📄'; break;
                                                default: echo '📄';
                                            }
                                            ?>
                                        </span>
                                        <span class="file-title"><?php echo htmlspecialchars($file['title'], ENT_QUOTES, 'UTF-8'); ?></span>
                                        <span class="file-type">.<?php echo htmlspecialchars($file['type'], ENT_QUOTES, 'UTF-8'); ?></span>
                                    </a>
                                <?php endforeach; ?>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </nav>
            </aside>

            <main class="content-area">
                <div class="content-header">
                    <h1 class="content-title"><?php echo htmlspecialchars($currentTitle, ENT_QUOTES, 'UTF-8'); ?></h1>
                </div>
                <div class="content-body">
                    <?php if ($currentContent): ?>
                        <?php echo $currentContent; ?>
                    <?php else: ?>
                        <div class="welcome-message">
                            <h2>🎯 Bienvenido al Sistema de Guías Temáticas</h2>
                            <p>Selecciona una guía de la lista lateral para comenzar a explorar el contenido, o ingresa una URL remota en el campo superior.</p>
                            <div class="features">
                                <div class="feature">
                                    <h3>📄 Archivos de Texto</h3>
                                    <p>Lee archivos .txt con formato optimizado para lectura</p>
                                </div>
                                <div class="feature">
                                    <h3>📝 Markdown</h3>
                                    <p>Procesa archivos .md con formato enriquecido</p>
                                </div>
                                <div class="feature">
                                    <h3>📋 JSON</h3>
                                    <p>Muestra datos estructurados de archivos .json</p>
                                </div>
                                <div class="feature">
                                    <h3>🌐 URLs Remotas</h3>
                                    <p>Carga contenido directamente desde URLs externas (solo HTTPS)</p>
                                </div>
                            </div>
                        </div>
                    <?php endif; ?>
                </div>
            </main>
        </div>
    </div>

    <footer class="footer">
        <div class="footer-content">
            <p><strong><a href='https://github.com/zidrave/visorweb/' target='_blank' class='link-github'> VisorWeb en Github</a></strong> estilo tutoriales by <strong>Zidrave Labs</strong></p>
        </div>
    </footer>

    <script>
(function () {
    function copyToClipboard(text) {
        if (!text || text.trim() === '') {
            return Promise.reject(new Error('No hay texto para copiar'));
        }
        if (navigator.clipboard && window.isSecureContext) {
            return navigator.clipboard.writeText(text);
        }
        return new Promise(function (resolve, reject) {
            try {
                const textarea = document.createElement('textarea');
                textarea.value = text;
                textarea.setAttribute('readonly', '');
                textarea.style.position = 'fixed';
                textarea.style.top = '-1000px';
                textarea.style.opacity = '0';
                document.body.appendChild(textarea);
                const selection = document.getSelection();
                const savedRange = selection && selection.rangeCount > 0 ? selection.getRangeAt(0) : null;
                textarea.select();
                const success = document.execCommand('copy');
                document.body.removeChild(textarea);
                if (savedRange) {
                    selection.removeAllRanges();
                    selection.addRange(savedRange);
                }
                success ? resolve() : reject(new Error('Fallo al copiar con execCommand'));
            } catch (e) {
                reject(e);
            }
        });
    }

    document.addEventListener('DOMContentLoaded', function () {
        document.querySelectorAll('pre.code-block').forEach(function (pre) {
            let code = pre.querySelector('code');
            if (!code) {
                code = document.createElement('code');
                code.textContent = pre.textContent;
                pre.textContent = '';
                pre.appendChild(code);
            }
            pre.classList.forEach(function (cls) {
                if (cls.startsWith('language-')) {
                    code.classList.add(cls);
                }
            });
            if (!pre.querySelector('.copy-btn')) {
                const btn = document.createElement('button');
                btn.className = 'copy-btn';
                btn.type = 'button';
                btn.textContent = 'Copiar';
                btn.addEventListener('click', function () {
                    const text = code.textContent || '';
                    copyToClipboard(text)
                        .then(function () {
                            btn.textContent = '¡Copiado!';
                            btn.classList.add('copied');
                            setTimeout(() => {
                                btn.textContent = 'Copiar';
                                btn.classList.remove('copied');
                            }, 1200);
                        })
                        .catch(function (err) {
                            btn.textContent = 'Error';
                            btn.classList.add('error');
                            btn.title = !window.isSecureContext
                                ? 'Copia no disponible sin HTTPS o localhost'
                                : err.message || 'No se pudo copiar';
                            setTimeout(() => {
                                btn.textContent = 'Copiar';
                                btn.classList.remove('error');
                                btn.removeAttribute('title');
                            }, 1500);
                        });
                });
                pre.appendChild(btn);
            }
            if (typeof hljs !== 'undefined') {
                try {
                    hljs.highlightElement(code);
                } catch (e) {
                    console.warn('Error al resaltar código:', e);
                }
            }
        });

        document.querySelectorAll('pre.json-display').forEach(function (pre) {
            let code = pre.querySelector('code');
            if (!code) {
                code = document.createElement('code');
                code.className = 'language-json';
                code.textContent = pre.textContent;
                pre.textContent = '';
                pre.appendChild(code);
            } else {
                code.classList.add('language-json');
            }
            if (typeof hljs !== 'undefined') {
                try {
                    hljs.highlightElement(code);
                } catch (e) {
                    console.warn('Error al resaltar JSON:', e);
                }
            }
        });
    });
})();
    </script>
</body>
</html>
