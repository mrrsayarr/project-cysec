const { spawn } = require('child_process');

exports.runPythonScript = function(scriptPath, callback) {
    const python = spawn('python', [scriptPath]);

    let output = '';
    let error = '';

    python.stdout.on('data', function (data) {
        output += data.toString();
    });

    python.stderr.on('data', function (data) {
        error += data.toString();
    });

    python.on('close', function(code) {
        console.log('Hata: ' + error + '\n' + 'Çıktı: ' + output); 
        
        if (code !== 0) {
            return callback(new Error(`Python script exited with code ${code}: ${error}`));
        }
        callback(null, output);
    });
};