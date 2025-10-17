package com.elf2uf2.gui;

import javafx.animation.FadeTransition;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.concurrent.Task;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.image.Image;
import javafx.scene.image.ImageView;

import javafx.scene.Scene;
import java.io.ByteArrayOutputStream;
import javafx.scene.control.*;
import javafx.scene.layout.*;
import javafx.scene.paint.Color;
import javafx.scene.text.Font;
import javafx.stage.FileChooser;
import javafx.stage.Stage;
import javafx.scene.text.FontWeight;
import javafx.util.Duration;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.zip.CRC32;

public class App extends Application {

    private TextField tfInput;
    private TextField tfOutput;
    private Button btnSelect;
    private Button btnSave;
    private ComboBox<String> cbFormat;
    private TextField tfBase;
    private Spinner<Integer> spBlock;
    private ComboBox<String> cbHashChoice;
    private Button btnConvert;
    private ProgressBar progress;
    private Label progressLabel;
    private Label statusLabel;
    private TextArea taHex;
    private TextArea taAscii;
    private TextArea taMeta;
    private byte[] currentImage = new byte[0];
    private long elfMinVaddr = 0;
    private DateTimeFormatter dtf = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private TextField tfMagic0;
    private TextField tfMagic1;
    private TextField tfEndMagic;
    private TextField tfFlags;
    private TextField tfFamily;
    private ComboBox<String> cbPresets;

    public static void main(String[] args) {
        launch(args);
    }

    @Override
    public void start(Stage stage) {
        stage.setTitle("ELF2UF2");

        Label title = new Label("ELF → UF2");
        title.setFont(Font.font("Consolas", FontWeight.BOLD, 24));
        title.setTextFill(Color.web("#c78cff"));

        tfInput = new TextField();
        tfInput.setEditable(false);
        tfInput.setPromptText("Select ELF / BIN");
        btnSelect = new Button("Select File");
        btnSelect.setOnAction(e -> onSelect(stage));

        tfOutput = new TextField();
        tfOutput.setEditable(false);
        tfOutput.setPromptText("Output");
        btnSave = new Button("Save As");
        btnSave.setOnAction(e -> onSave(stage));

        cbFormat = new ComboBox<>();
        cbFormat.getItems().addAll("UF2", "BIN", "Intel HEX");
        cbFormat.setValue("UF2");

        HBox fileRow1 = new HBox(8, tfInput, btnSelect);
        fileRow1.setAlignment(Pos.CENTER_LEFT);
        HBox fileRow2 = new HBox(8, tfOutput, btnSave, cbFormat);
        fileRow2.setAlignment(Pos.CENTER_LEFT);

        tfBase = new TextField("0x10000000");
        spBlock = new Spinner<>(16, 480, 256, 16);
        spBlock.setEditable(true);
        cbHashChoice = new ComboBox<>();
        cbHashChoice.getItems().addAll("SHA-256", "CRC32", "None");
        cbHashChoice.setValue("SHA-256");

        tfMagic0 = new TextField("0x0A324655");
        tfMagic1 = new TextField("0x9E5D5157");
        tfEndMagic = new TextField("0x0AB16F30");
        tfFlags = new TextField("0x00000000");
        tfFamily = new TextField("0xE48BFF56");

        cbPresets = new ComboBox<>();
        cbPresets.getItems().addAll(
            "Raspberry Pi Pico (RP2040)",
            "Raspberry Pi Pico W",
            "Adafruit Feather RP2040",
            "Adafruit ItsyBitsy RP2040",
            "Pimoroni Tiny 2040",
            "Seeed XIAO RP2040",
            "SparkFun Pro Micro RP2040",
            "Arduino Nano RP2040 Connect",
            "Seeed Wio RP2040",
            "Custom"
        );
        cbPresets.setValue("Raspberry Pi Pico (RP2040)");
        cbPresets.setOnAction(e -> applyPreset(cbPresets.getValue()));

        GridPane settings = new GridPane();
        settings.setHgap(10);
        settings.setVgap(8);
        settings.add(new Label("Base Addr"), 0, 0);
        settings.add(tfBase, 1, 0);
        settings.add(new Label("Block size (payload)"), 0, 1);
        settings.add(spBlock, 1, 1);
        settings.add(new Label("Hash"), 0, 2);
        settings.add(cbHashChoice, 1, 2);

        GridPane headerGrid = new GridPane();
        headerGrid.setHgap(10);
        headerGrid.setVgap(6);
        headerGrid.add(new Label("Magic Start 0"), 0, 0);
        headerGrid.add(tfMagic0, 1, 0);
        headerGrid.add(new Label("Magic Start 1"), 0, 1);
        headerGrid.add(tfMagic1, 1, 1);
        headerGrid.add(new Label("Magic End"), 0, 2);
        headerGrid.add(tfEndMagic, 1, 2);
        headerGrid.add(new Label("Flags"), 0, 3);
        headerGrid.add(tfFlags, 1, 3);
        headerGrid.add(new Label("Family ID"), 0, 4);
        headerGrid.add(tfFamily, 1, 4);
        headerGrid.add(new Label("Presets"), 0, 5);
        headerGrid.add(cbPresets, 1, 5);

        btnConvert = new Button("Convert");
        btnConvert.setOnAction(e -> onConvert());
        progress = new ProgressBar(0);
        progress.setVisible(false);
        progress.setPrefWidth(320);
        progressLabel = new Label("");
        progressLabel.setTextFill(Color.web("#d8baf6"));
        progressLabel.setFont(Font.font("Consolas", 12));
        statusLabel = new Label("");
        statusLabel.setTextFill(Color.web("#bdb0d8"));
        statusLabel.setVisible(false);
        statusLabel.setManaged(false);


        HBox convertRow = new HBox(12, btnConvert, progress);
        convertRow.setAlignment(Pos.CENTER_LEFT);

        taHex = new TextArea();
        taHex.setEditable(false);
        taHex.setFont(Font.font("Monospaced", 12));
        taHex.setWrapText(false);

        taAscii = new TextArea();
        taAscii.setEditable(false);
        taAscii.setFont(Font.font("Monospaced", 12));
        taAscii.setWrapText(false);
        taHex.setPrefHeight(800);
        taAscii.setPrefHeight(800);

        HBox hexBox = new HBox(6, taHex, taAscii);
        hexBox.setAlignment(Pos.CENTER_LEFT);

        taMeta = new TextArea();
        taMeta.setEditable(false);
        taMeta.setPrefRowCount(60);
        taMeta.setFont(Font.font("Consolas", 12));
        taMeta.setPromptText("Metadata summary (ELF segments etc.)");


        VBox left = new VBox(10, title, fileRow1, fileRow2, settings, headerGrid, convertRow, progressLabel, statusLabel, new Label("Output"), taMeta);
        left.setPadding(new Insets(14));
        left.setStyle(
            "-fx-background-color: #07060a;" +
            "-fx-background-radius:8;" +
            "-fx-border-color:#2b0f36;" +
            "-fx-border-radius:8;" +
            "-fx-padding:12;"
        );

        left.setPrefWidth(600);

        VBox right = new VBox(10, new Label("Hex Dump"), hexBox);
        right.setPadding(new Insets(12));
        right.setStyle("-fx-background-color: #06040a; -fx-background-radius:8; -fx-padding:12; -fx-border-color:#2b0f36; -fx-border-radius:8;");
        right.setPrefWidth(480);

        HBox main = new HBox(12, left, right);
        main.setPadding(new Insets(12));

        BorderPane root = new BorderPane();
        root.setCenter(main);
        root.setBottom(null);


        Scene scene = new Scene(root, 1100, 820);
        stage.setResizable(false);
        scene.getStylesheets().add("data:text/css," + css().replace("\n", "%0A"));
        stage.setScene(scene);
        stage.getIcons().add(new javafx.scene.image.Image(getClass().getResource("/pico.png").toExternalForm()));

        stage.show();

        applyPreset(cbPresets.getValue());
    }

    private void applyPreset(String name) {
        switch (name) {
            case "Raspberry Pi Pico (RP2040)":
            case "Raspberry Pi Pico W":
            case "Pimoroni Tiny 2040":
            case "Seeed XIAO RP2040":
            case "SparkFun Pro Micro RP2040":
            case "Arduino Nano RP2040 Connect":
            case "Seeed Wio RP2040":
                tfBase.setText("0x10000000");
                tfFamily.setText("0xE48BFF56");
                spBlock.getValueFactory().setValue(256);
                tfFlags.setText("0x00000000");
                break;
            case "Adafruit Feather RP2040":
            case "Adafruit ItsyBitsy RP2040":
                tfBase.setText("0x10000000");
                tfFamily.setText("0xE48BFF56");
                spBlock.getValueFactory().setValue(240);
                tfFlags.setText("0x00000000");
                break;
            default:
                break;
        }
    }

    private void onSelect(Stage stage) {
        FileChooser fc = new FileChooser();
        fc.getExtensionFilters().addAll(new FileChooser.ExtensionFilter("ELF or BIN", "*.elf", "*.bin"), new FileChooser.ExtensionFilter("All files", "*.*"));
        File f = fc.showOpenDialog(stage);
        if (f == null) return;
        tfInput.setText(f.getAbsolutePath());
        appendStatus("Selected: " + f.getName());
        try {
            byte[] raw = Files.readAllBytes(f.toPath());
            if (isElf(raw)) {
                ParsedELF p = parseELF(raw);
                currentImage = p.image;
                elfMinVaddr = p.minVaddr;
                tfBase.setText(String.format("0x%08X", elfMinVaddr));
                taMeta.setText(p.summary());
                appendStatus(String.format("ELF parsed: min_vaddr=0x%08X size=%d", elfMinVaddr, currentImage.length));
            } else {
                currentImage = raw;
                taMeta.setText("Binary file: size=" + currentImage.length);
                appendStatus("Binary loaded: size=" + currentImage.length);
            }
            refreshHexView();
        } catch (Exception ex) {
            appendStatus("Error loading file: " + ex.getMessage());
            showAlert("Error: " + ex.getMessage());
        }
    }

    private void onSave(Stage stage) {
        FileChooser fc = new FileChooser();
        fc.getExtensionFilters().addAll(new FileChooser.ExtensionFilter("UF2", "*.uf2"), new FileChooser.ExtensionFilter("BIN", "*.bin"), new FileChooser.ExtensionFilter("Intel HEX", "*.hex"));
        File f = fc.showSaveDialog(stage);
        if (f == null) return;
        tfOutput.setText(f.getAbsolutePath());
        appendStatus("Output: " + f.getName());
    }

    private void onConvert() {
        progress.progressProperty().unbind();
        progress.setProgress(0);
        progress.setVisible(true);
        progressLabel.setText("Starting new conversion...");
        btnConvert.setDisable(false);
        if (tfInput.getText().isEmpty() || tfOutput.getText().isEmpty()) {
            showAlert("Select input and output first");
            return;
        }
        progress.setProgress(0);
        progress.setVisible(true);
        progressLabel.setText("Initializing");
        btnConvert.setDisable(true);
        statusLabel.setTextFill(Color.web("#ffd3ff"));
        if (Thread.activeCount() > 2) System.gc();
        Task<Void> task = new Task<>() {
            @Override
            protected Void call() throws Exception {
                String format = cbFormat.getValue();
                long base = parseLongSafe(tfBase.getText().trim(), 0x10000000L);
                int payload = spBlock.getValue();
                String hashChoice = cbHashChoice.getValue();
                updateProgressAndLabel(5, "Preparing image");
                byte[] img = currentImage;
                if ("UF2".equals(format)) {
                    updateProgressAndLabel(15, "Splitting into UF2 blocks");
                    Integer family = parseIntSafeHex(tfFamily.getText().trim(), null);
                    int flags = (int) parseLongSafe(tfFlags.getText().trim(), 0);
                    long magic0 = parseLongSafe(tfMagic0.getText().trim(), 0x0A324655L);
                    long magic1 = parseLongSafe(tfMagic1.getText().trim(), 0x9E5D5157L);
                    long magicEnd = parseLongSafe(tfEndMagic.getText().trim(), 0x0AB16F30L);
                    List<byte[]> blocks = makeUf2Blocks(img, base, family, flags, payload, (byte)0x00, magic0, magic1, magicEnd);
                    updateProgressAndLabel(40, "Writing UF2 blocks to disk");
                    writeUf2(tfOutput.getText(), blocks);
                    updateProgressAndLabel(65, "Verifying UF2 content");
                    byte[] recon = reconstructFromBlocks(blocks, img.length);
                    if (recon.length != img.length || !Arrays.equals(recon, img)) throw new Exception("Verification failed: UF2 reconstructed data differs");
                } else if ("BIN".equals(format)) {
                    updateProgressAndLabel(25, "Writing BIN to disk");
                    Files.write(new File(tfOutput.getText()).toPath(), img);
                    updateProgressAndLabel(60, "Verifying BIN content");
                    byte[] out = Files.readAllBytes(new File(tfOutput.getText()).toPath());
                    if (out.length != img.length || !Arrays.equals(out, img)) throw new Exception("Verification failed: BIN differs");
                } else {
                    updateProgressAndLabel(20, "Generating Intel HEX");
                    String hex = buildIntelHex(img, base);
                    updateProgressAndLabel(45, "Writing HEX to disk");
                    Files.write(new File(tfOutput.getText()).toPath(), hex.getBytes());
                    updateProgressAndLabel(70, "Verifying HEX content (length check)");
                    byte[] out = Files.readAllBytes(new File(tfOutput.getText()).toPath());
                    if (out.length == 0) throw new Exception("Verification failed: HEX file empty");
                }
                updateProgressAndLabel(85, "Computing hash");
                Map<String, Object> meta = new LinkedHashMap<>();
                meta.put("input", tfInput.getText());
                meta.put("output", tfOutput.getText());
                meta.put("size", img.length);
                meta.put("base", String.format("0x%08X", base));
                meta.put("time", LocalDateTime.now().toString());
                if ("SHA-256".equals(hashChoice)) meta.put("sha256", computeSHA(img));
                else if ("CRC32".equals(hashChoice)) meta.put("crc32", computeCRC(img));
                String metaStr = toJsonPretty(meta);
                Platform.runLater(() -> taMeta.setText(metaStr));
                updateProgressAndLabel(100, "Finalizing");
                return null;
            }

            @Override
            protected void succeeded() {
                progress.progressProperty().unbind();
                smoothHideProgress();
                btnConvert.setDisable(false);
                progressLabel.setText("");
                statusLabel.setTextFill(Color.web("#b7f7d8"));
            }

            @Override
            protected void failed() {
                progress.progressProperty().unbind();
                smoothHideProgress();
                btnConvert.setDisable(false);
                progressLabel.setText("Error occurred.");
                statusLabel.setTextFill(Color.web("#ff9fbf"));
                appendStatus("Conversion error");
            }
        };
        progress.progressProperty().bind(task.progressProperty());
        new Thread(task, "convert-thread").start();
    }

    private void updateProgressAndLabel(int percent, String label) {
        double p = Math.max(0, Math.min(100, percent)) / 100.0;
        updateProgress(p);
        Platform.runLater(() -> progressLabel.setText(label + " (" + percent + "% )"));
        try { Thread.sleep(90); } catch (InterruptedException ignored) {}
    }

    private void updateProgress(double value) {
        Platform.runLater(() -> progress.setProgress(value));
    }

    private boolean isElf(byte[] raw) {
        return raw.length >= 4 && raw[0] == 0x7F && raw[1] == 'E' && raw[2] == 'L' && raw[3] == 'F';
    }

    private static class ParsedELF {
        long minVaddr;
        byte[] image;
        List<Map<String, Object>> ph;
        ParsedELF(long m, byte[] i, List<Map<String, Object>> ph) { minVaddr = m; image = i; this.ph = ph; }
        String summary() {
            StringBuilder sb = new StringBuilder();
            sb.append("ELF parsed\n");
            sb.append("min_vaddr: ").append(String.format("0x%08X", minVaddr)).append("\n");
            sb.append("segments:\n");
            for (Map<String, Object> s: ph) sb.append("  ").append(s.toString()).append("\n");
            return sb.toString();
        }
    }

    private ParsedELF parseELF(byte[] raw) throws Exception {
        ByteBuffer bb = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
        int ei_class = raw[4] & 0xFF;
        boolean is64 = (ei_class == 2);
        if (is64) {
            long e_phoff = bb.getLong(32);
            int e_phentsize = Short.toUnsignedInt(bb.getShort(54));
            int e_phnum = Short.toUnsignedInt(bb.getShort(56));
            List<Map<String,Object>> phlist = new ArrayList<>();
            long min = Long.MAX_VALUE, max = 0;
            for (int i=0;i<e_phnum;i++){
                int off = (int)(e_phoff + (long)i*e_phentsize);
                ByteBuffer pb = ByteBuffer.wrap(raw, off, e_phentsize).order(ByteOrder.LITTLE_ENDIAN);
                int p_type = pb.getInt(0);
                long p_offset = pb.getLong(8);
                long p_vaddr = pb.getLong(16);
                long p_filesz = pb.getLong(32);
                long p_memsz = pb.getLong(40);
                if (p_type==1 && p_filesz>0){
                    min = Math.min(min, p_vaddr);
                    max = Math.max(max, p_vaddr + p_memsz);
                    Map<String,Object> m = new LinkedHashMap<>();
                    m.put("type","PT_LOAD");
                    m.put("offset",p_offset);
                    m.put("vaddr",p_vaddr);
                    m.put("filesz",p_filesz);
                    m.put("memsz",p_memsz);
                    phlist.add(m);
                }
            }
            int total = (int)(max - min);
            byte[] image = new byte[total];
            for (Map<String,Object> e: phlist){
                long v = (long)e.get("vaddr");
                int off = (int)(v - min);
                int fs = (int)((long)e.get("filesz"));
                int fo = (int)((long)e.get("offset"));
                System.arraycopy(raw, fo, image, off, fs);
            }
            return new ParsedELF(min, image, phlist);
        } else {
            int e_phoff = bb.getInt(28);
            int e_phentsize = Short.toUnsignedInt(bb.getShort(42));
            int e_phnum = Short.toUnsignedInt(bb.getShort(44));
            List<Map<String,Object>> phlist = new ArrayList<>();
            long min = Long.MAX_VALUE, max = 0;
            for (int i=0;i<e_phnum;i++){
                int off = e_phoff + i*e_phentsize;
                ByteBuffer pb = ByteBuffer.wrap(raw, off, e_phentsize).order(ByteOrder.LITTLE_ENDIAN);
                int p_type = pb.getInt(0);
                int p_offset = pb.getInt(4);
                int p_vaddr = pb.getInt(8);
                int p_filesz = pb.getInt(16);
                int p_memsz = pb.getInt(20);
                if (p_type==1 && p_filesz>0){
                    min = Math.min(min, Integer.toUnsignedLong(p_vaddr));
                    max = Math.max(max, Integer.toUnsignedLong(p_vaddr) + Integer.toUnsignedLong(p_memsz));
                    Map<String,Object> m = new LinkedHashMap<>();
                    m.put("type","PT_LOAD");
                    m.put("offset",p_offset);
                    m.put("vaddr",Integer.toUnsignedLong(p_vaddr));
                    m.put("filesz",Integer.toUnsignedLong(p_filesz));
                    m.put("memsz",Integer.toUnsignedLong(p_memsz));
                    phlist.add(m);
                }
            }
            int total = (int)(max - min);
            byte[] image = new byte[total];
            for (Map<String,Object> e: phlist){
                long v = (long)e.get("vaddr");
                int off = (int)(v - min);
                int fs = (int)((long)e.get("filesz"));
                int fo = (int)((long)e.get("offset"));
                System.arraycopy(raw, fo, image, off, fs);
            }
            return new ParsedELF(min, image, phlist);
        }
    }


    private List<byte[]> makeUf2Blocks(byte[] data, long base, Integer family, int flags, int payloadSize, byte pad, long magic0, long magic1, long magicEnd) {
        int fileSize = data.length;
        int numBlocks = Math.max(1, (fileSize + payloadSize - 1) / payloadSize);
        List<byte[]> out = new ArrayList<>(numBlocks);
        for (int i = 0; i < numBlocks; i++) {
            int start = i * payloadSize;
            int end = Math.min(fileSize, start + payloadSize);
            byte[] payload = new byte[payloadSize];
            Arrays.fill(payload, pad);
            System.arraycopy(data, start, payload, 0, end - start);
            ByteBuffer buf = ByteBuffer.allocate(512).order(ByteOrder.LITTLE_ENDIAN);
            buf.putInt((int)magic0);
            buf.putInt((int)magic1);
            buf.putInt(flags);
            buf.putInt((int)(base + start));
            buf.putInt(payloadSize);
            buf.putInt(i);
            buf.putInt(numBlocks);
            buf.putInt(fileSize);
            buf.put(payload);
            int written = 4*8 + payloadSize;
            int remain = 512 - 4 - written;
            if (remain > 0) buf.put(new byte[remain]);

            if (family != null) {
                int pos = 0x1F8;
                buf.putInt(pos, family);
            }

            buf.putInt(0x01FC, (int)magicEnd);
            out.add(buf.array());
        }
        return out;
    }

    private void writeUf2(String path, List<byte[]> blocks) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(path)) {
            for (byte[] b : blocks) fos.write(b);
            fos.getFD().sync();
        }
    }

    private byte[] reconstructFromBlocks(List<byte[]> blocks, int expectedLen) {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        for (byte[] b : blocks) {
            if (b.length >= 512) {
                ByteBuffer buf = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN);
                int payloadSize = buf.getInt(4*4);
                int headerBytes = 4*8;
                int copyLen = Math.min(payloadSize, b.length - headerBytes - 4);
                if (copyLen > 0) {
                    bout.write(b, headerBytes, copyLen);
                    if (bout.size() >= expectedLen) break;
                }
            }
        }
        byte[] all = bout.toByteArray();
        if (all.length > expectedLen) {
            byte[] t = new byte[expectedLen];
            System.arraycopy(all, 0, t, 0, expectedLen);
            return t;
        }
        return all;
    }

    private String buildIntelHex(byte[] data, long base) {
        StringBuilder sb = new StringBuilder();
        int addr = (int) base;
        int ptr = 0;
        while (ptr < data.length) {
            int len = Math.min(16, data.length - ptr);
            int a = addr & 0xFFFF;
            byte[] chunk = Arrays.copyOfRange(data, ptr, ptr + len);
            int sum = len + (a >> 8) + (a & 0xFF);
            sb.append(String.format(":%02X%04X00", len, a));
            for (byte bt : chunk) { sb.append(String.format("%02X", bt & 0xFF)); sum += bt & 0xFF; }
            int cks = ((~sum + 1) & 0xFF);
            sb.append(String.format("%02X\n", cks));
            ptr += len;
            addr += len;
        }
        sb.append(":00000001FF\n");
        return sb.toString();
    }

    private void refreshHexView() {
        StringBuilder hex = new StringBuilder();
        StringBuilder ascii = new StringBuilder();
        int cols = 16;
        for (int i = 0; i < currentImage.length; i += cols) {
            hex.append(String.format("%08X: ", i));
            for (int j = 0; j < cols; j++) {
                int idx = i + j;
                if (idx < currentImage.length) hex.append(String.format("%02X ", currentImage[idx]));
                else hex.append("   ");
            }
            hex.append("  ");
            for (int j = 0; j < cols; j++) {
                int idx = i + j;
                if (idx < currentImage.length) {
                    int b = currentImage[idx] & 0xFF;
                    ascii.append(b >= 32 && b < 127 ? (char) b : '.');
                } else ascii.append(' ');
            }
            hex.append("\n");
            ascii.append("\n");
            if (i > 65536) {
                hex.append("... (truncated preview)\n");
                ascii.append("... (truncated preview)\n");
                break;
            }
        }
        Platform.runLater(() -> { taHex.setText(hex.toString()); taAscii.setText(ascii.toString()); });
    }

    private String computeSHA(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] d = md.digest(data);
        StringBuilder sb = new StringBuilder();
        for (byte b : d) sb.append(String.format("%02x", b & 0xFF));
        return sb.toString();
    }

    private String computeCRC(byte[] data) {
        CRC32 crc = new CRC32();
        crc.update(data);
        return String.format("%08x", crc.getValue());
    }

    private void appendStatus(String s) {
        String time = LocalDateTime.now().format(dtf);
        Platform.runLater(() -> statusLabel.setText(time + " — " + s));
        String reset = "\u001B[0m";
        String magenta = "\u001B[35m";
        System.out.println(magenta + "[" + time + "] " + s + reset);
    }

    private long parseLongSafe(String s, long def) {
        if (s == null || s.isEmpty()) return def;
        try {
            String t = s.trim().toLowerCase();
            if (t.startsWith("0x")) return Long.parseLong(t.substring(2), 16);
            return Long.parseLong(t);
        } catch (Exception e) {
            return def;
        }
    }

    private Integer parseIntSafeHex(String s, Integer def) {
        if (s == null || s.isEmpty()) return def;
        try {
            String t = s.trim().toLowerCase();
            if (t.startsWith("0x")) return (int)Long.parseLong(t.substring(2), 16);
            return Integer.parseInt(t);
        } catch (Exception e) {
            return def;
        }
    }

    private String toJsonPretty(Map<String,Object> m) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        for (Map.Entry<String,Object> e : m.entrySet()) {
            sb.append("  \"").append(e.getKey()).append("\": ");
            Object v = e.getValue();
            if (v instanceof Number) sb.append(v);
            else sb.append("\"").append(String.valueOf(v)).append("\"");
            sb.append(",\n");
        }
        if (!m.isEmpty()) sb.setLength(sb.length() - 2);
        sb.append("\n}\n");
        return sb.toString();
    }

    private void showAlert(String m) {
        Platform.runLater(() -> {
            Alert a = new Alert(Alert.AlertType.ERROR);
            a.setTitle("ELF2UF2");
            a.setHeaderText(null);
            a.setContentText(m);
            a.showAndWait();
        });
    }

    private void smoothHideProgress() {
        Platform.runLater(() -> {
            FadeTransition ft = new FadeTransition(Duration.millis(600), progress);
            ft.setFromValue(1.0);
            ft.setToValue(0.0);
            ft.setOnFinished(ev -> {
                progress.setVisible(false);
                progress.setOpacity(1.0);
                progressLabel.setText("");
            });
            ft.play();
        });
    }
















    private String css() {
        return """
            .root {
                -fx-font-family: 'Consolas', monospace;
                -fx-background-color: linear-gradient(#010008,#04000b);
            }
            Label {
                -fx-text-fill: #c78cff;
            }

            .combo-box, .combo-box .list-cell {
    -fx-background-color: #1c122a;
    -fx-text-fill: #d8baf6;
}

.combo-box, .combo-box .list-cell {
    -fx-background-color: #1c122a;
    -fx-text-fill: #d8baf6;
}

.spinner {
    -fx-background-color: #1c122a;
    -fx-border-color: #2b0f36;
    -fx-border-radius: 6;
    -fx-background-radius: 6;
}
.spinner .text-field {
    -fx-background-color: #1c122a;
    -fx-text-fill: #c78cff;
}
.spinner .increment-arrow-button, .spinner .decrement-arrow-button {
    -fx-background-color: #1c122a;
    -fx-border-color: #2b0f36;
    -fx-border-radius: 4;
}
.spinner .increment-arrow-button:hover, .spinner .decrement-arrow-button:hover {
    -fx-background-color: #8a56d6;
}

.scroll-bar:vertical .track, .scroll-bar:horizontal .track {
    -fx-background-color: #1c122a;
}

.scroll-bar:vertical .thumb, .scroll-bar:horizontal .thumb {
    -fx-background-color: #c78cff;
    -fx-background-insets: 0;
    -fx-background-radius: 4;
}

.scroll-bar:vertical .thumb:hover, .scroll-bar:horizontal .thumb:hover {
    -fx-background-color: #8a56d6;
}

.scroll-bar .increment-button, .scroll-bar .decrement-button {
    -fx-background-color: #1c122a;
    -fx-background-insets: 0;
    -fx-padding: 2;
}




            TextField, ComboBox, Spinner {
                -fx-background-color: #0b0610;
                -fx-text-fill: #d8baf6;
                -fx-border-color: #2b0f36;
                -fx-border-radius: 6;
                -fx-background-radius: 6;
                -fx-padding: 6;
            }
            TextField:focused, ComboBox:focused, Spinner:focused {
                -fx-border-color: #b26cff;
                -fx-effect: dropshadow(three-pass-box, rgba(189,127,255,0.4), 5, 0.3, 0, 0);
            }

            Button {
                -fx-background-color: linear-gradient(#c78cff,#8a56d6);
                -fx-text-fill: #0b0210;
                -fx-background-radius: 8;
                -fx-padding: 6 12 6 12;
                -fx-cursor: hand;
                -fx-font-weight: bold;
            }
            Button:hover {
                -fx-background-color: linear-gradient(#e0aaff,#a77fe0);
                -fx-effect: dropshadow(three-pass-box, rgba(199,140,255,0.5), 8, 0.4, 0, 0);
            }

            TextArea {
                -fx-control-inner-background: #030102;
                -fx-text-fill: #d7c0ff;
                -fx-font-family: monospace;
                -fx-border-color: #2b0f36;
                -fx-border-radius: 6;
                -fx-background-radius: 6;
            }
            """;
    }

}
