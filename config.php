<?php
/* =============================================================================
   config.php — jūsu iestatījumi. Aizpildiet visus [AIZPILDIET] laukus.
   Šo failu augšupielādējiet vienreiz; atjauninot index.php vai admin.php,
   šis fails netiek pārrakstīts, tāpēc parole un rekvizīti saglabājas.
   ============================================================================= */
if (basename((string)($_SERVER['SCRIPT_FILENAME'] ?? '')) === 'config.php') { http_response_code(404); exit; }

const CONFIG = [
    /* --- Datubāze (MySQL / MariaDB). Šīs vērtības atradīsiet hostinga vadības panelī,
           tur pat, kur atverat phpMyAdmin. --- */
    'db_host'          => 'localhost',
    'db_name'          => '[AIZPILDIET datubāzes nosaukums]',
    'db_user'          => '[AIZPILDIET lietotājs]',
    'db_pass'          => '[AIZPILDIET parole]',

    /* --- Uzņēmuma rekvizīti (redzami vietnē) --- */
    'company_name'     => 'SIA [AIZPILDIET]',
    'reg_number'       => '[AIZPILDIET]',
    'vat_number'       => '[AIZPILDIET]',
    'legal_address'    => '[AIZPILDIET juridiskā adrese]',
    'camp_address'     => '[AIZPILDIET nometnes norises vieta]',
    'bank'             => '[AIZPILDIET banka, IBAN]',
    'email'            => '[AIZPILDIET]@example.lv',
    'phone'            => '+371 [AIZPILDIET]',
    'dpo_email'        => '[AIZPILDIET]@example.lv',
    'supervisory'      => 'Datu valsts inspekcija, www.dvi.gov.lv',
    'instructor_cert'  => '[AIZPILDIET sertifikāta nosaukums, piem. LSF/ISIA]',
    'hosting_provider' => '[AIZPILDIET nosaukums, valsts]',
    'accounting'       => '[AIZPILDIET]',

    /* --- Citi --- */
    'policy_updated'   => '10.11.2026',   // mainiet, kad maināt noteikumus vai politikas
    'retention_months' => 12,             // pieteikumi tiek dzēsti N mēnešus pēc maiņas beigām
];
