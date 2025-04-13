# Commander

Commander is a productivity tool that helps you:

- Organize and save frequently used commands by project and task
- Store account information securely with encryption
- Quickly capture and retrieve commands via hotkeys and drag-and-drop
- Stay on top of other applications for easy access

## Features

- **Project & Task Organization**: Organize commands hierarchically by projects and tasks
- **Always-on-Top Mode**: Stay accessible while working with other applications
- **Compact Mode**: Toggle between full and compact views to minimize screen space
- **Secure Storage**: All data is encrypted with a password
- **Hotkeys**: Quick keyboard shortcuts for capturing text (Ctrl+Alt+C) and toggling compact mode (Ctrl+Alt+M)
- **Drag & Drop Support**: Easily add commands by dragging text
- **Command History**: Save and reuse frequently used commands

## Installation

1. Clone or download this repository
2. Install the dependencies:

```bash
pip install -r requirements.txt
```

### Troubleshooting Dependencies

If you have issues with tkinterdnd2 installation, you can install it manually:

```bash
pip install --no-deps tkinterdnd2
```

## Usage

Run the application:

```bash
python commander.py
```

### First time setup

- On first run, you will be asked to set an encryption password
- The program will automatically create a default project and task

### Basic workflow

1. **Select or create a project**
2. **Select or create a task** within that project
3. **Capture commands** in one of three ways:
   - Use Ctrl+Alt+C to capture selected text from any application
   - Drag and drop text onto the Commander window
   - Copy text to clipboard and use "Capture from Clipboard" button

### Compact Mode

Toggle compact mode with Ctrl+Alt+M to keep Commander accessible but unobtrusive.

### Copying commands

Select any saved command and click "Copy to Clipboard" to use it in other applications.

## Security

All data is encrypted using Fernet symmetric encryption from the cryptography library. Your password is never stored - instead, it's used to derive the encryption key. 