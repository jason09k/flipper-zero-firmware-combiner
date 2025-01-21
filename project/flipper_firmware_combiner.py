"""
Flipper Firmware Combiner
A modern GUI application for combining Flipper Zero firmware files with enhanced validation and security.
"""
import os
import tarfile
import shutil
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Optional, Dict, Set
from dataclasses import dataclass
import threading
import hashlib
from queue import Queue
import json
import tempfile
import ttkthemes

@dataclass
class FirmwareMetadata:
    """Metadata for firmware files."""
    version: str
    target: str
    timestamp: str
    components: Set[str]
    
    @classmethod
    def from_file(cls, file_path: Path) -> Optional['FirmwareMetadata']:
        """Extract metadata from a firmware file."""
        try:
            with tarfile.open(file_path, "r:gz") as tar:
                metadata_file = next(
                    (m for m in tar.getmembers() if m.name.endswith('metadata.json')),
                    None
                )
                if metadata_file:
                    metadata_content = tar.extractfile(metadata_file).read()
                    data = json.loads(metadata_content)
                    return cls(
                        version=data.get('version', 'unknown'),
                        target=data.get('target', 'unknown'),
                        timestamp=data.get('build_date', 'unknown'),
                        components=set(data.get('components', []))
                    )
        except Exception as e:
            logging.error(f"Failed to extract metadata: {e}")
            return None

@dataclass
class FirmwareFile:
    """Data class to represent a firmware file with metadata."""
    path: Path
    size: int
    hash: str
    metadata: Optional[FirmwareMetadata] = None
    is_valid: bool = False

    @staticmethod
    def from_path(path: Path) -> 'FirmwareFile':
        """Create a FirmwareFile instance from a path."""
        size = path.stat().st_size
        with open(path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
        firmware = FirmwareFile(path=path, size=size, hash=file_hash)
        firmware.metadata = FirmwareMetadata.from_file(path)
        return firmware

class FirmwareValidator:
    """Handles firmware file validation and integrity checks."""
    
    REQUIRED_FILES = {'update.fuf', 'update.fap', 'metadata.json'}
    MAX_SIZE = 1024 * 1024 * 50  # 50MB limit
    ALLOWED_EXTENSIONS = {'.tgz', '.tar.gz'}
    
    @staticmethod
    def validate_firmware(file_path: Path) -> tuple[bool, str]:
        """Validates a firmware file for integrity and content."""
        try:
            if not file_path.exists():
                return False, "File does not exist"
                
            if file_path.suffix not in FirmwareValidator.ALLOWED_EXTENSIONS:
                return False, "Invalid file extension"
                
            if file_path.stat().st_size > FirmwareValidator.MAX_SIZE:
                return False, f"File exceeds maximum size of {FirmwareValidator.MAX_SIZE // (1024*1024)}MB"
                
            with tarfile.open(file_path, "r:gz") as tar:
                file_list = {member.name for member in tar.getmembers()}
                missing_files = FirmwareValidator.REQUIRED_FILES - file_list
                
                if missing_files:
                    return False, f"Missing required files: {', '.join(missing_files)}"
                    
                # Security: Check for path traversal attempts
                for member in tar.getmembers():
                    if member.name.startswith('/') or '..' in member.name:
                        return False, "Security: Invalid file paths detected"
                        
                # Verify metadata
                metadata = FirmwareMetadata.from_file(file_path)
                if not metadata:
                    return False, "Invalid or missing metadata"
                    
            return True, "Valid firmware file"
            
        except tarfile.TarError as e:
            return False, f"Invalid tar file: {str(e)}"
        except Exception as e:
            return False, f"Validation error: {str(e)}"

class FirmwareCombiner:
    """Core logic for combining firmware files."""
    
    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.temp_dir = Path(tempfile.mkdtemp())
        
    def __del__(self):
        """Cleanup temporary files."""
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
            
    def combine_firmware_files(self, firmware_files: List[FirmwareFile], 
                             progress_callback) -> Optional[Path]:
        """Combines multiple firmware files into a single archive."""
        try:
            work_dir = self.temp_dir / "firmware_work"
            work_dir.mkdir(parents=True, exist_ok=True)
            
            # Process each firmware file
            total_files = len(firmware_files)
            for idx, firmware in enumerate(firmware_files, 1):
                progress_callback(
                    (idx / total_files) * 50,
                    f"Processing firmware {idx}/{total_files}: {firmware.path.name}"
                )
                
                extract_dir = work_dir / f"firmware_{idx}"
                extract_dir.mkdir(parents=True)
                
                with tarfile.open(firmware.path, "r:gz") as tar:
                    # Security check before extraction
                    for member in tar.getmembers():
                        if member.name.startswith('/') or '..' in member.name:
                            raise SecurityError(f"Security violation in {firmware.path.name}")
                    tar.extractall(extract_dir)
            
            progress_callback(75, "Creating combined firmware...")
            
            # Generate output filename with timestamp and metadata
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = self.output_dir / f"flipper_combined_firmware_{timestamp}.tgz"
            
            # Create metadata
            metadata = {
                'created_at': datetime.now().isoformat(),
                'source_files': [
                    {
                        'name': f.path.name,
                        'size': f.size,
                        'hash': f.hash,
                        'metadata': {
                            'version': f.metadata.version if f.metadata else 'unknown',
                            'target': f.metadata.target if f.metadata else 'unknown',
                            'timestamp': f.metadata.timestamp if f.metadata else 'unknown',
                            'components': list(f.metadata.components) if f.metadata else []
                        } if f.metadata else None
                    } for f in firmware_files
                ]
            }
            
            # Write metadata
            with open(work_dir / 'firmware_metadata.json', 'w') as f:
                json.dump(metadata, f, indent=2)
            
            # Create final archive with progress tracking
            with tarfile.open(output_path, "w:gz") as tar:
                total_items = sum(1 for _ in work_dir.rglob('*'))
                processed = 0
                
                for item in work_dir.rglob('*'):
                    tar.add(item, arcname=item.relative_to(work_dir))
                    processed += 1
                    progress = 75 + (processed / total_items * 25)
                    progress_callback(progress, f"Archiving: {processed}/{total_items}")
            
            progress_callback(100, "Firmware combination complete!")
            return output_path
            
        except Exception as e:
            logging.error(f"Error combining firmware: {str(e)}")
            raise
        finally:
            if self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)

class ModernUI(ttkthemes.ThemedTk):
    """Modern themed UI for the Flipper Firmware Combiner."""
    
    def __init__(self):
        super().__init__(theme="equilux")
        
        self.title("🐬 Flipper Firmware Combiner")
        self.geometry("800x600")
        self.configure(bg='#2E3440')
        
        # Initialize variables
        self.output_dir = Path.home() / "Documents" / "FirmwareCombiner"
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.firmware_files: List[FirmwareFile] = []
        self.processing = False
        
        # Setup logging
        self.setup_logging()
        
        # Build UI
        self.setup_ui()
        
    def setup_logging(self):
        """Configure application logging."""
        log_path = self.output_dir / "firmware_combiner.log"
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            filename=log_path,
            filemode="a"
        )
        
    def setup_ui(self):
        """Create the main UI elements."""
        # Main container
        self.main_frame = ttk.Frame(self)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Header
        header_frame = ttk.Frame(self.main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 20))
        
        ttk.Label(
            header_frame,
            text="🐬 Flipper Firmware Combiner",
            font=('Helvetica', 24, 'bold')
        ).pack(side=tk.LEFT)
        
        # Drop zone
        self.drop_frame = ttk.LabelFrame(
            self.main_frame,
            text="Drop Zone",
            padding=20
        )
        self.drop_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        drop_label = ttk.Label(
            self.drop_frame,
            text="Drop .tgz firmware files here or click to browse",
            font=('Helvetica', 12)
        )
        drop_label.pack(expand=True)
        
        # Enable drag and drop
        self.drop_frame.bind('<Button-1>', self.browse_files)
        self.drop_frame.drop_target_register(tk.DND_FILES)
        self.drop_frame.dnd_bind('<<Drop>>', self.handle_drop)
        
        # File list with metadata
        files_frame = ttk.LabelFrame(
            self.main_frame,
            text="Selected Firmware Files",
            padding=10
        )
        files_frame.pack(fill=tk.BOTH, pady=10)
        
        # Treeview for files
        self.file_tree = ttk.Treeview(
            files_frame,
            columns=('Size', 'Version', 'Target', 'Status'),
            show='headings',
            height=5
        )
        
        self.file_tree.heading('Size', text='Size')
        self.file_tree.heading('Version', text='Version')
        self.file_tree.heading('Target', text='Target')
        self.file_tree.heading('Status', text='Status')
        
        self.file_tree.pack(fill=tk.BOTH, expand=True)
        
        # Progress section
        progress_frame = ttk.Frame(self.main_frame)
        progress_frame.pack(fill=tk.X, pady=20)
        
        self.status_label = ttk.Label(
            progress_frame,
            text="Ready to combine firmware files",
            font=('Helvetica', 10)
        )
        self.status_label.pack()
        
        self.progress = ttk.Progressbar(
            progress_frame,
            orient="horizontal",
            length=300,
            mode="determinate"
        )
        self.progress.pack(fill=tk.X, pady=5)
        
        # Buttons
        button_frame = ttk.Frame(self.main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(
            button_frame,
            text="Clear Files",
            command=self.clear_files
        ).pack(side=tk.LEFT, padx=5)
        
        self.combine_button = ttk.Button(
            button_frame,
            text="Combine Firmware",
            command=self.start_combination
        )
        self.combine_button.pack(side=tk.RIGHT, padx=5)
        
        # Output directory info
        ttk.Label(
            self.main_frame,
            text=f"Output Directory: {self.output_dir}",
            font=('Helvetica', 8)
        ).pack(pady=10)
        
    def handle_drop(self, event):
        """Handle files dropped onto the drop zone."""
        files = event.data.split()
        self.add_firmware_files([Path(f) for f in files])
        
    def browse_files(self, event=None):
        """Open file browser for firmware selection."""
        files = filedialog.askopenfilenames(
            title="Select Firmware Files",
            filetypes=[("Firmware files", "*.tgz")]
        )
        if files:
            self.add_firmware_files([Path(f) for f in files])
            
    def add_firmware_files(self, file_paths: List[Path]):
        """Add and validate new firmware files."""
        for path in file_paths:
            firmware = FirmwareFile.from_path(path)
            is_valid, message = FirmwareValidator.validate_firmware(path)
            firmware.is_valid = is_valid
            
            self.firmware_files.append(firmware)
            
            # Update tree view with metadata
            size_str = f"{firmware.size / 1024:.1f} KB"
            version = firmware.metadata.version if firmware.metadata else 'Unknown'
            target = firmware.metadata.target if firmware.metadata else 'Unknown'
            status = "Valid" if is_valid else "Invalid"
            
            self.file_tree.insert(
                '',
                'end',
                text=path.name,
                values=(size_str, version, target, status)
            )
            
    def clear_files(self):
        """Clear all selected firmware files."""
        self.firmware_files.clear()
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
            
    def update_progress(self, value, status_text):
        """Update progress bar and status text."""
        self.progress['value'] = value
        self.status_label['text'] = status_text
        self.update_idletasks()
        
    def start_combination(self):
        """Start the firmware combination process."""
        if not self.firmware_files:
            messagebox.showwarning(
                "Warning",
                "Please select firmware files first!"
            )
            return
            
        if not any(f.is_valid for f in self.firmware_files):
            messagebox.showerror(
                "Error",
                "No valid firmware files selected!"
            )
            return
            
        if self.processing:
            return
            
        self.processing = True
        self.combine_button['state'] = 'disabled'
        
        # Start processing thread
        threading.Thread(
            target=self.process_firmware,
            daemon=True
        ).start()
        
    def process_firmware(self):
        """Process and combine firmware files."""
        try:
            combiner = FirmwareCombiner(self.output_dir)
            valid_files = [f for f in self.firmware_files if f.is_valid]
            
            output_path = combiner.combine_firmware_files(
                valid_files,
                self.update_progress
            )
            
            if output_path:
                messagebox.showinfo(
                    "Success",
                    f"Combined firmware saved to:\n{output_path}"
                )
                
        except Exception as e:
            logging.error(f"Error during combination: {str(e)}")
            messagebox.showerror(
                "Error",
                f"An error occurred: {str(e)}"
            )
            self.update_progress(0, "Error occurred during combination")
            
        finally:
            self.processing = False
            self.combine_button['state'] = 'normal'

def main():
    """Application entry point."""
    app = ModernUI()
    app.mainloop()

if __name__ == "__main__":
    main()