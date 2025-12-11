// Editor Manager
window.EditorManager = (function () {
    let editor = null;
    let currentPath = null;
    let ignoreChange = false;

    function init() {
        if (typeof require === 'undefined') {
            console.error('Monaco Editor loader not found. Check internet connection or CDN.');
            return;
        }
        require.config({ paths: { vs: 'https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min/vs' } });
        require(['vs/editor/editor.main'], function () {
            editor = monaco.editor.create(document.getElementById('editor-container'), {
                value: '',
                language: 'python',
                theme: 'vs-dark',
                automaticLayout: true,
                minimap: { enabled: true },
                fontSize: 14
            });

            // Event Listeners
            editor.onDidChangeModelContent((e) => {
                if (ignoreChange || !currentPath) return;

                e.changes.forEach(change => {
                    const operation = {
                        type: change.text ? 'insert' : 'delete',
                        position: change.rangeOffset,
                        text: change.text || '',
                        length: change.rangeLength
                    };

                    socket.emit('edit_operation', {
                        module_path: currentPath,
                        operation: operation
                    });
                });
            });

            editor.onDidChangeCursorPosition((e) => {
                if (!currentPath) return;
                const position = editor.getPosition();
                socket.emit('cursor_update', {
                    module_path: currentPath,
                    cursor: { line: position.lineNumber, column: position.column }
                });
            });

            // Save shortcut (Ctrl+S)
            editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS, function () {
                saveCurrentFile();
            });

            // Initialize
            init();

            return {
                openFile,
                clear
            };
        }); // End of require callback
    } // End of init function

    // Initialize when DOM is ready
    document.addEventListener('DOMContentLoaded', init);

    function openFile(path) {
        currentPath = path;
        socket.emit('read_file', { file: path });
    }

    function clear() {
        if (editor) {
            editor.setValue('');
            currentPath = null;
        }
    }

    function saveCurrentFile() {
        if (!currentPath) return;
        socket.emit('save_file', {
            file: currentPath,
            content: editor.getValue()
        });
    }

    return {
        openFile,
        clear
    };
})();
