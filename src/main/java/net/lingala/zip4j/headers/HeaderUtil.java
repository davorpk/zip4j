package net.lingala.zip4j.headers;

import static net.lingala.zip4j.util.InternalZipConstants.*;
import static net.lingala.zip4j.util.Zip4jUtil.*;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;

import net.lingala.zip4j.exception.ZipException;
import net.lingala.zip4j.model.FileHeader;
import net.lingala.zip4j.model.ZipModel;
import net.lingala.zip4j.util.InternalZipConstants;

public class HeaderUtil {

  public static FileHeader getFileHeader(final ZipModel zipModel, String fileName) throws ZipException {
    FileHeader fileHeader = getFileHeaderWithExactMatch(zipModel, fileName);

    if (fileHeader == null) {
      fileName = fileName.replaceAll("\\\\", "/");
      fileHeader = getFileHeaderWithExactMatch(zipModel, fileName);

      if (fileHeader == null) {
        fileName = fileName.replaceAll("/", "\\\\");
        fileHeader = getFileHeaderWithExactMatch(zipModel, fileName);
      }
    }

    return fileHeader;
  }

  public static String decodeStringWithCharset(final byte[] data, final boolean isUtf8Encoded, final Charset charset) {
    if (charset != null) {
      return new String(data, charset);
    }

    if (isUtf8Encoded) {
      return new String(data, InternalZipConstants.CHARSET_UTF_8);
    }

    try {
      return new String(data, ZIP_STANDARD_CHARSET_NAME);
    } catch (final UnsupportedEncodingException e) {
      return new String(data);
    }
  }

  public static byte[] getBytesFromString(final String string, final Charset charset) {
    if (charset == null) {
      return string.getBytes(ZIP4J_DEFAULT_CHARSET);
    }

    return string.getBytes(charset);
  }

  public static long getOffsetStartOfCentralDirectory(final ZipModel zipModel) {
    if (zipModel.isZip64Format()) {
      return zipModel.getZip64EndOfCentralDirectoryRecord().getOffsetStartCentralDirectoryWRTStartDiskNumber();
    }

    return zipModel.getEndOfCentralDirectoryRecord().getOffsetOfStartOfCentralDirectory();
  }

  public static long getSizeOfCentralDirectory(final ZipModel zipModel) {
      if (zipModel.isZip64Format()) {
        return zipModel.getZip64EndOfCentralDirectoryRecord().getSizeOfCentralDirectory();
      }

      return zipModel.getEndOfCentralDirectoryRecord().getSizeOfCentralDirectory();
    }

  public static List<FileHeader> getFileHeadersUnderDirectory(final List<FileHeader> allFileHeaders, final String fileName) {
    final List<FileHeader> fileHeadersUnderDirectory = new ArrayList<>();
    for (final FileHeader fileHeader : allFileHeaders) {
      if (fileHeader.getFileName().startsWith(fileName)) {
        fileHeadersUnderDirectory.add(fileHeader);
      }
    }
    return fileHeadersUnderDirectory;
  }

  public static long getTotalUncompressedSizeOfAllFileHeaders(final List<FileHeader> fileHeaders) {
    long totalUncompressedSize = 0;
    for (final FileHeader fileHeader : fileHeaders) {
      if (fileHeader.getZip64ExtendedInfo() != null &&
          fileHeader.getZip64ExtendedInfo().getUncompressedSize() > 0) {
        totalUncompressedSize += fileHeader.getZip64ExtendedInfo().getUncompressedSize();
      } else {
        totalUncompressedSize += fileHeader.getUncompressedSize();
      }
    }
    return totalUncompressedSize;
  }

  private static FileHeader getFileHeaderWithExactMatch(final ZipModel zipModel, final String fileName) throws ZipException {
    if (zipModel == null) {
      throw new ZipException("zip model is null, cannot determine file header with exact match for fileName: "
          + fileName);
    }

    if (!isStringNotNullAndNotEmpty(fileName)) {
      throw new ZipException("file name is null, cannot determine file header with exact match for fileName: "
          + fileName);
    }

    if (zipModel.getCentralDirectory() == null) {
      throw new ZipException("central directory is null, cannot determine file header with exact match for fileName: "
          + fileName);
    }

    if (zipModel.getCentralDirectory().getFileHeaders() == null) {
      throw new ZipException("file Headers are null, cannot determine file header with exact match for fileName: "
          + fileName);
    }

    if (zipModel.getCentralDirectory().getFileHeaders().size() == 0) {
      return null;
    }

    for (final FileHeader fileHeader : zipModel.getCentralDirectory().getFileHeaders()) {
      final String fileNameForHdr = fileHeader.getFileName();
      if (!isStringNotNullAndNotEmpty(fileNameForHdr)) {
        continue;
      }

      if (fileName.equals(fileNameForHdr)) {
        return fileHeader;
      }
    }

    return null;
  }
}
