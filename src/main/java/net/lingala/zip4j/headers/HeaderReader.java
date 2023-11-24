/*
 * Copyright 2010 Srikanth Reddy Lingala
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.lingala.zip4j.headers;

import static net.lingala.zip4j.headers.HeaderUtil.*;
import static net.lingala.zip4j.util.BitUtils.*;
import static net.lingala.zip4j.util.InternalZipConstants.*;
import static net.lingala.zip4j.util.Zip4jUtil.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.RandomAccessFile;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import net.lingala.zip4j.exception.ZipException;
import net.lingala.zip4j.io.inputstream.NumberedSplitRandomAccessFile;
import net.lingala.zip4j.model.*;
import net.lingala.zip4j.model.enums.AesKeyStrength;
import net.lingala.zip4j.model.enums.AesVersion;
import net.lingala.zip4j.model.enums.CompressionMethod;
import net.lingala.zip4j.model.enums.EncryptionMethod;
import net.lingala.zip4j.util.RawIO;

/**
 * Helper class to read header information for the zip file
 */
public class HeaderReader
{
    private ZipModel zipModel;
    private final RawIO rawIO = new RawIO();
    private final byte[] intBuff = new byte[4];

    public ZipModel readAllHeaders(final RandomAccessFile zip4jRaf, final Zip4jConfig zip4jConfig) throws IOException
    {

        if (zip4jRaf.length() == 0)
        {
            return new ZipModel();
        }

        if (zip4jRaf.length() < ENDHDR)
        {
            throw new ZipException("Zip file size less than minimum expected zip file size. " +
                    "Probably not a zip file or a corrupted zip file");
        }

        zipModel = new ZipModel();

        try
        {
            zipModel.setEndOfCentralDirectoryRecord(readEndOfCentralDirectoryRecord(zip4jRaf, rawIO, zip4jConfig));
        }
        catch (final ZipException e)
        {
            throw e;
        }
        catch (final IOException e)
        {
            e.printStackTrace();
            throw new ZipException("Zip headers not found. Probably not a zip file or a corrupted zip file", e);
        }

        if (zipModel.getEndOfCentralDirectoryRecord().getTotalNumberOfEntriesInCentralDirectory() == 0)
        {
            return zipModel;
        }

        // If file is Zip64 format, Zip64 headers have to be read before reading
        // central directory
        zipModel.setZip64EndOfCentralDirectoryLocator(readZip64EndOfCentralDirectoryLocator(zip4jRaf, rawIO,
                zipModel.getEndOfCentralDirectoryRecord().getOffsetOfEndOfCentralDirectory()));

        if (zipModel.isZip64Format())
        {
            zipModel.setZip64EndOfCentralDirectoryRecord(readZip64EndCentralDirRec(zip4jRaf, rawIO));
            if (zipModel.getZip64EndOfCentralDirectoryRecord() != null
                    && zipModel.getZip64EndOfCentralDirectoryRecord().getNumberOfThisDisk() > 0)
            {
                zipModel.setSplitArchive(true);
            }
            else
            {
                zipModel.setSplitArchive(false);
            }
        }

        zipModel.setCentralDirectory(readCentralDirectory(zip4jRaf, rawIO, zip4jConfig.getCharset()));

        return zipModel;
    }


    private EndOfCentralDirectoryRecord readEndOfCentralDirectoryRecord(final RandomAccessFile zip4jRaf, final RawIO rawIO,
            final Zip4jConfig zip4jConfig) throws IOException
    {

        final long offsetEndOfCentralDirectory = locateOffsetOfEndOfCentralDirectory(zip4jRaf);
        seekInCurrentPart(zip4jRaf, offsetEndOfCentralDirectory + 4);

        final EndOfCentralDirectoryRecord endOfCentralDirectoryRecord = new EndOfCentralDirectoryRecord();
        endOfCentralDirectoryRecord.setSignature(HeaderSignature.END_OF_CENTRAL_DIRECTORY);
        endOfCentralDirectoryRecord.setNumberOfThisDisk(rawIO.readShortLittleEndian(zip4jRaf));
        endOfCentralDirectoryRecord.setNumberOfThisDiskStartOfCentralDir(rawIO.readShortLittleEndian(zip4jRaf));
        endOfCentralDirectoryRecord.setTotalNumberOfEntriesInCentralDirectoryOnThisDisk(
                rawIO.readShortLittleEndian(zip4jRaf));
        endOfCentralDirectoryRecord.setTotalNumberOfEntriesInCentralDirectory(rawIO.readShortLittleEndian(zip4jRaf));
        endOfCentralDirectoryRecord.setSizeOfCentralDirectory(rawIO.readIntLittleEndian(zip4jRaf));
        endOfCentralDirectoryRecord.setOffsetOfEndOfCentralDirectory(offsetEndOfCentralDirectory);

        zip4jRaf.readFully(intBuff);
        endOfCentralDirectoryRecord.setOffsetOfStartOfCentralDirectory(rawIO.readLongLittleEndian(intBuff, 0));

        final int commentLength = rawIO.readShortLittleEndian(zip4jRaf);
        endOfCentralDirectoryRecord.setComment(readZipComment(zip4jRaf, commentLength, zip4jConfig.getCharset()));

        zipModel.setSplitArchive(endOfCentralDirectoryRecord.getNumberOfThisDisk() > 0);
        return endOfCentralDirectoryRecord;
    }


    private CentralDirectory readCentralDirectory(final RandomAccessFile zip4jRaf, final RawIO rawIO, final Charset charset) throws IOException
    {
        final CentralDirectory centralDirectory = new CentralDirectory();
        final List<FileHeader> fileHeaders = new ArrayList<>();

        final long offSetStartCentralDir = HeaderUtil.getOffsetStartOfCentralDirectory(zipModel);
        final int sizeOfCentralDir = (int) HeaderUtil.getSizeOfCentralDirectory(zipModel);
        final long centralDirEntryCount = getNumberOfEntriesInCentralDirectory(zipModel);

        zip4jRaf.seek(offSetStartCentralDir);
        final byte[] centralDirBuff = new byte[sizeOfCentralDir];
        zip4jRaf.readFully(centralDirBuff);
        
        try (ByteArrayInputStream is = new ByteArrayInputStream(centralDirBuff))
        {
            final byte[] shortBuff = new byte[2];
            final byte[] intBuff = new byte[4];
            for (int i = 0; i < centralDirEntryCount; i++)
            {
                final FileHeader fileHeader = new FileHeader();
                is.read(intBuff);
                if (rawIO.readIntLittleEndian(intBuff) != HeaderSignature.CENTRAL_DIRECTORY.getValue())
                {
                    throw new ZipException("Expected central directory entry not found (#" + (i + 1) + ")");
                }
                fileHeader.setSignature(HeaderSignature.CENTRAL_DIRECTORY);
                is.read(shortBuff);
                fileHeader.setVersionMadeBy(rawIO.readShortLittleEndian(shortBuff, 0));
                is.read(shortBuff);
                fileHeader.setVersionNeededToExtract(rawIO.readShortLittleEndian(shortBuff, 0));

                final byte[] generalPurposeFlags = new byte[2];
                is.read(generalPurposeFlags);
                fileHeader.setEncrypted(isBitSet(generalPurposeFlags[0], 0));
                fileHeader.setDataDescriptorExists(isBitSet(generalPurposeFlags[0], 3));
                fileHeader.setFileNameUTF8Encoded(isBitSet(generalPurposeFlags[1], 3));
                fileHeader.setGeneralPurposeFlag(generalPurposeFlags.clone());

                is.read(shortBuff);
                fileHeader.setCompressionMethod(CompressionMethod.getCompressionMethodFromCode(rawIO.readShortLittleEndian(shortBuff, 0)));
                is.read(intBuff);
                fileHeader.setLastModifiedTime(rawIO.readIntLittleEndian(intBuff));

                is.read(intBuff);
                fileHeader.setCrc(rawIO.readLongLittleEndian(intBuff, 0));
                is.read(intBuff);
                fileHeader.setCompressedSize(rawIO.readLongLittleEndian(intBuff, 0));
                is.read(intBuff);
                fileHeader.setUncompressedSize(rawIO.readLongLittleEndian(intBuff, 0));

                is.read(shortBuff);
                final int fileNameLength = rawIO.readShortLittleEndian(shortBuff, 0);
                fileHeader.setFileNameLength(fileNameLength);

                is.read(shortBuff);
                final int extraFieldLength = rawIO.readShortLittleEndian(shortBuff, 0);
                fileHeader.setExtraFieldLength(extraFieldLength);

                is.read(shortBuff);
                final int fileCommentLength = rawIO.readShortLittleEndian(shortBuff, 0);
                fileHeader.setFileCommentLength(fileCommentLength);

                is.read(shortBuff);
                fileHeader.setDiskNumberStart(rawIO.readShortLittleEndian(shortBuff, 0));

                is.read(shortBuff);
                fileHeader.setInternalFileAttributes(shortBuff.clone());

                is.read(intBuff);
                fileHeader.setExternalFileAttributes(intBuff.clone());

                is.read(intBuff);
                fileHeader.setOffsetLocalHeader(rawIO.readLongLittleEndian(intBuff, 0));

                if (fileNameLength > 0)
                {
                    final byte[] fileNameBuff = new byte[fileNameLength];
                    is.read(fileNameBuff);
                    final String fileName = decodeStringWithCharset(fileNameBuff, fileHeader.isFileNameUTF8Encoded(), charset);
                    fileHeader.setFileName(fileName);
                }
                else
                {
                    throw new ZipException("Invalid entry name in file header");
                }

                fileHeader.setDirectory(isDirectory(fileHeader.getExternalFileAttributes(), fileHeader.getFileName()));
                readExtraDataRecords(is, fileHeader);
                readZip64ExtendedInfo(fileHeader, rawIO);
                readAesExtraDataRecord(fileHeader, rawIO);

                if (fileCommentLength > 0)
                {
                    final byte[] fileCommentBuff = new byte[fileCommentLength];
                    is.read(fileCommentBuff);
                    fileHeader.setFileComment(decodeStringWithCharset(fileCommentBuff, fileHeader.isFileNameUTF8Encoded(), charset));
                }

                if (fileHeader.isEncrypted())
                {
                    if (fileHeader.getAesExtraDataRecord() != null)
                    {
                        fileHeader.setEncryptionMethod(EncryptionMethod.AES);
                    }
                    else
                    {
                        fileHeader.setEncryptionMethod(EncryptionMethod.ZIP_STANDARD);
                    }
                }

                fileHeaders.add(fileHeader);
            }
        }
        centralDirectory.setFileHeaders(fileHeaders);

        final DigitalSignature digitalSignature = new DigitalSignature();
        if (rawIO.readIntLittleEndian(zip4jRaf) == HeaderSignature.DIGITAL_SIGNATURE.getValue())
        {
            digitalSignature.setSignature(HeaderSignature.DIGITAL_SIGNATURE);
            digitalSignature.setSizeOfData(rawIO.readShortLittleEndian(zip4jRaf));

            if (digitalSignature.getSizeOfData() > 0)
            {
                final byte[] signatureDataBuff = new byte[digitalSignature.getSizeOfData()];
                zip4jRaf.readFully(signatureDataBuff);
                digitalSignature.setSignatureData(new String(signatureDataBuff));
            }
        }

        return centralDirectory;
    }


    private void readExtraDataRecords(final InputStream inputStream, final FileHeader fileHeader)
            throws IOException
    {
        final int extraFieldLength = fileHeader.getExtraFieldLength();
        if (extraFieldLength <= 0)
        {
            return;
        }

        fileHeader.setExtraDataRecords(readExtraDataRecords(inputStream, extraFieldLength));
    }


    private void readExtraDataRecords(final InputStream inputStream, final LocalFileHeader localFileHeader)
            throws IOException
    {
        final int extraFieldLength = localFileHeader.getExtraFieldLength();
        if (extraFieldLength <= 0)
        {
            return;
        }

        localFileHeader.setExtraDataRecords(readExtraDataRecords(inputStream, extraFieldLength));

    }


    private List<ExtraDataRecord> readExtraDataRecords(final InputStream inputStream, final int extraFieldLength)
            throws IOException
    {

        if (extraFieldLength < 4)
        {
            if (extraFieldLength > 0)
            {
                inputStream.skip(extraFieldLength);
            }

            return null;
        }

        final byte[] extraFieldBuf = new byte[extraFieldLength];
        readFully(inputStream, extraFieldBuf);

        try
        {
            return parseExtraDataRecords(extraFieldBuf, extraFieldLength);
        }
        catch (final Exception e)
        {
            // Ignore any errors when parsing extra data records
            return Collections.emptyList();
        }
    }


    private List<ExtraDataRecord> parseExtraDataRecords(final byte[] extraFieldBuf, final int extraFieldLength)
    {
        int counter = 0;
        final List<ExtraDataRecord> extraDataRecords = new ArrayList<>();
        while (counter < extraFieldLength)
        {
            final ExtraDataRecord extraDataRecord = new ExtraDataRecord();
            final int header = rawIO.readShortLittleEndian(extraFieldBuf, counter);
            extraDataRecord.setHeader(header);
            counter += 2;

            final int sizeOfRec = rawIO.readShortLittleEndian(extraFieldBuf, counter);
            extraDataRecord.setSizeOfData(sizeOfRec);
            counter += 2;

            if (sizeOfRec > 0)
            {
                final byte[] data = new byte[sizeOfRec];
                System.arraycopy(extraFieldBuf, counter, data, 0, sizeOfRec);
                extraDataRecord.setData(data);
            }
            counter += sizeOfRec;
            extraDataRecords.add(extraDataRecord);
        }
        return extraDataRecords.size() > 0 ? extraDataRecords : null;
    }


    private Zip64EndOfCentralDirectoryLocator readZip64EndOfCentralDirectoryLocator(final RandomAccessFile zip4jRaf,
            final RawIO rawIO, final long offsetEndOfCentralDirectoryRecord) throws IOException
    {

        final Zip64EndOfCentralDirectoryLocator zip64EndOfCentralDirectoryLocator = new Zip64EndOfCentralDirectoryLocator();

        setFilePointerToReadZip64EndCentralDirLoc(zip4jRaf, offsetEndOfCentralDirectoryRecord);

        final int signature = rawIO.readIntLittleEndian(zip4jRaf);
        if (signature == HeaderSignature.ZIP64_END_CENTRAL_DIRECTORY_LOCATOR.getValue())
        {
            zipModel.setZip64Format(true);
            zip64EndOfCentralDirectoryLocator.setSignature(HeaderSignature.ZIP64_END_CENTRAL_DIRECTORY_LOCATOR);
        }
        else
        {
            zipModel.setZip64Format(false);
            return null;
        }

        zip64EndOfCentralDirectoryLocator.setNumberOfDiskStartOfZip64EndOfCentralDirectoryRecord(
                rawIO.readIntLittleEndian(zip4jRaf));
        zip64EndOfCentralDirectoryLocator.setOffsetZip64EndOfCentralDirectoryRecord(
                rawIO.readLongLittleEndian(zip4jRaf));
        zip64EndOfCentralDirectoryLocator.setTotalNumberOfDiscs(rawIO.readIntLittleEndian(zip4jRaf));

        return zip64EndOfCentralDirectoryLocator;
    }


    private Zip64EndOfCentralDirectoryRecord readZip64EndCentralDirRec(final RandomAccessFile zip4jRaf, final RawIO rawIO)
            throws IOException
    {

        if (zipModel.getZip64EndOfCentralDirectoryLocator() == null)
        {
            throw new ZipException("invalid zip64 end of central directory locator");
        }

        final long offSetStartOfZip64CentralDir = zipModel.getZip64EndOfCentralDirectoryLocator()
                .getOffsetZip64EndOfCentralDirectoryRecord();

        if (offSetStartOfZip64CentralDir < 0)
        {
            throw new ZipException("invalid offset for start of end of central directory record");
        }

        zip4jRaf.seek(offSetStartOfZip64CentralDir);

        final Zip64EndOfCentralDirectoryRecord zip64EndOfCentralDirectoryRecord = new Zip64EndOfCentralDirectoryRecord();

        final int signature = rawIO.readIntLittleEndian(zip4jRaf);
        if (signature != HeaderSignature.ZIP64_END_CENTRAL_DIRECTORY_RECORD.getValue())
        {
            throw new ZipException("invalid signature for zip64 end of central directory record");
        }
        zip64EndOfCentralDirectoryRecord.setSignature(HeaderSignature.ZIP64_END_CENTRAL_DIRECTORY_RECORD);
        zip64EndOfCentralDirectoryRecord.setSizeOfZip64EndCentralDirectoryRecord(rawIO.readLongLittleEndian(zip4jRaf));
        zip64EndOfCentralDirectoryRecord.setVersionMadeBy(rawIO.readShortLittleEndian(zip4jRaf));
        zip64EndOfCentralDirectoryRecord.setVersionNeededToExtract(rawIO.readShortLittleEndian(zip4jRaf));
        zip64EndOfCentralDirectoryRecord.setNumberOfThisDisk(rawIO.readIntLittleEndian(zip4jRaf));
        zip64EndOfCentralDirectoryRecord.setNumberOfThisDiskStartOfCentralDirectory(rawIO.readIntLittleEndian(zip4jRaf));
        zip64EndOfCentralDirectoryRecord.setTotalNumberOfEntriesInCentralDirectoryOnThisDisk(
                rawIO.readLongLittleEndian(zip4jRaf));
        zip64EndOfCentralDirectoryRecord.setTotalNumberOfEntriesInCentralDirectory(rawIO.readLongLittleEndian(zip4jRaf));
        zip64EndOfCentralDirectoryRecord.setSizeOfCentralDirectory(rawIO.readLongLittleEndian(zip4jRaf));
        zip64EndOfCentralDirectoryRecord.setOffsetStartCentralDirectoryWRTStartDiskNumber(
                rawIO.readLongLittleEndian(zip4jRaf));

        // zip64 extensible data sector
        // 44 is the size of fixed variables in this record
        final long extDataSecSize = zip64EndOfCentralDirectoryRecord.getSizeOfZip64EndCentralDirectoryRecord() - 44;
        if (extDataSecSize > 0)
        {
            final byte[] extDataSecRecBuf = new byte[(int) extDataSecSize];
            zip4jRaf.readFully(extDataSecRecBuf);
            zip64EndOfCentralDirectoryRecord.setExtensibleDataSector(extDataSecRecBuf);
        }

        return zip64EndOfCentralDirectoryRecord;
    }


    private void readZip64ExtendedInfo(final FileHeader fileHeader, final RawIO rawIO)
    {
        if (fileHeader.getExtraDataRecords() == null || fileHeader.getExtraDataRecords().size() <= 0)
        {
            return;
        }

        final Zip64ExtendedInfo zip64ExtendedInfo = readZip64ExtendedInfo(fileHeader.getExtraDataRecords(), rawIO,
                fileHeader.getUncompressedSize(), fileHeader.getCompressedSize(), fileHeader.getOffsetLocalHeader(),
                fileHeader.getDiskNumberStart());

        if (zip64ExtendedInfo == null)
        {
            return;
        }

        fileHeader.setZip64ExtendedInfo(zip64ExtendedInfo);

        if (zip64ExtendedInfo.getUncompressedSize() != -1)
        {
            fileHeader.setUncompressedSize(zip64ExtendedInfo.getUncompressedSize());
        }

        if (zip64ExtendedInfo.getCompressedSize() != -1)
        {
            fileHeader.setCompressedSize(zip64ExtendedInfo.getCompressedSize());
        }

        if (zip64ExtendedInfo.getOffsetLocalHeader() != -1)
        {
            fileHeader.setOffsetLocalHeader(zip64ExtendedInfo.getOffsetLocalHeader());
        }

        if (zip64ExtendedInfo.getDiskNumberStart() != -1)
        {
            fileHeader.setDiskNumberStart(zip64ExtendedInfo.getDiskNumberStart());
        }
    }


    private void readZip64ExtendedInfo(final LocalFileHeader localFileHeader, final RawIO rawIO) throws ZipException
    {
        if (localFileHeader == null)
        {
            throw new ZipException("file header is null in reading Zip64 Extended Info");
        }

        if (localFileHeader.getExtraDataRecords() == null || localFileHeader.getExtraDataRecords().size() <= 0)
        {
            return;
        }

        final Zip64ExtendedInfo zip64ExtendedInfo = readZip64ExtendedInfo(localFileHeader.getExtraDataRecords(), rawIO,
                localFileHeader.getUncompressedSize(), localFileHeader.getCompressedSize(), 0, 0);

        if (zip64ExtendedInfo == null)
        {
            return;
        }

        localFileHeader.setZip64ExtendedInfo(zip64ExtendedInfo);

        if (zip64ExtendedInfo.getUncompressedSize() != -1)
        {
            localFileHeader.setUncompressedSize(zip64ExtendedInfo.getUncompressedSize());
        }

        if (zip64ExtendedInfo.getCompressedSize() != -1)
        {
            localFileHeader.setCompressedSize(zip64ExtendedInfo.getCompressedSize());
        }
    }


    private Zip64ExtendedInfo readZip64ExtendedInfo(final List<ExtraDataRecord> extraDataRecords, final RawIO rawIO,
            final long uncompressedSize, final long compressedSize, final long offsetLocalHeader,
            final int diskNumberStart)
    {

        for (final ExtraDataRecord extraDataRecord : extraDataRecords)
        {
            if (extraDataRecord == null)
            {
                continue;
            }

            if (HeaderSignature.ZIP64_EXTRA_FIELD_SIGNATURE.getValue() == extraDataRecord.getHeader())
            {

                final Zip64ExtendedInfo zip64ExtendedInfo = new Zip64ExtendedInfo();
                final byte[] extraData = extraDataRecord.getData();

                if (extraDataRecord.getSizeOfData() <= 0)
                {
                    return null;
                }

                int counter = 0;
                if (counter < extraDataRecord.getSizeOfData() && uncompressedSize == ZIP_64_SIZE_LIMIT)
                {
                    zip64ExtendedInfo.setUncompressedSize(rawIO.readLongLittleEndian(extraData, counter));
                    counter += 8;
                }

                if (counter < extraDataRecord.getSizeOfData() && compressedSize == ZIP_64_SIZE_LIMIT)
                {
                    zip64ExtendedInfo.setCompressedSize(rawIO.readLongLittleEndian(extraData, counter));
                    counter += 8;
                }

                if (counter < extraDataRecord.getSizeOfData() && offsetLocalHeader == ZIP_64_SIZE_LIMIT)
                {
                    zip64ExtendedInfo.setOffsetLocalHeader(rawIO.readLongLittleEndian(extraData, counter));
                    counter += 8;
                }

                if (counter < extraDataRecord.getSizeOfData() && diskNumberStart == ZIP_64_NUMBER_OF_ENTRIES_LIMIT)
                {
                    zip64ExtendedInfo.setDiskNumberStart(rawIO.readIntLittleEndian(extraData, counter));
                }

                return zip64ExtendedInfo;
            }
        }
        return null;
    }


    private void setFilePointerToReadZip64EndCentralDirLoc(final RandomAccessFile zip4jRaf,
            final long offsetEndOfCentralDirectoryRecord) throws IOException
    {
        // Now the file pointer is at the end of signature of Central Dir Rec
        // Seek back with the following values
        // 4 -> total number of disks
        // 8 -> relative offset of the zip64 end of central directory record
        // 4 -> number of the disk with the start of the zip64 end of central
        // directory
        // 4 -> zip64 end of central dir locator signature
        // Refer to Appnote for more information
        seekInCurrentPart(zip4jRaf, offsetEndOfCentralDirectoryRecord - 4 - 8 - 4 - 4);
    }


    public LocalFileHeader readLocalFileHeader(final InputStream inputStream, final Charset charset) throws IOException
    {
        final LocalFileHeader localFileHeader = new LocalFileHeader();
        final byte[] intBuff = new byte[4];

        // signature
        int sig = rawIO.readIntLittleEndian(inputStream);
        if (sig == HeaderSignature.TEMPORARY_SPANNING_MARKER.getValue())
        {
            sig = rawIO.readIntLittleEndian(inputStream);
        }
        if (sig != HeaderSignature.LOCAL_FILE_HEADER.getValue())
        {
            return null;
        }
        localFileHeader.setSignature(HeaderSignature.LOCAL_FILE_HEADER);
        localFileHeader.setVersionNeededToExtract(rawIO.readShortLittleEndian(inputStream));

        final byte[] generalPurposeFlags = new byte[2];
        if (readFully(inputStream, generalPurposeFlags) != 2)
        {
            throw new ZipException("Could not read enough bytes for generalPurposeFlags");
        }
        localFileHeader.setEncrypted(isBitSet(generalPurposeFlags[0], 0));
        localFileHeader.setDataDescriptorExists(isBitSet(generalPurposeFlags[0], 3));
        localFileHeader.setFileNameUTF8Encoded(isBitSet(generalPurposeFlags[1], 3));
        localFileHeader.setGeneralPurposeFlag(generalPurposeFlags.clone());

        localFileHeader.setCompressionMethod(CompressionMethod.getCompressionMethodFromCode(
                rawIO.readShortLittleEndian(inputStream)));
        localFileHeader.setLastModifiedTime(rawIO.readIntLittleEndian(inputStream));

        readFully(inputStream, intBuff);
        localFileHeader.setCrc(rawIO.readLongLittleEndian(intBuff, 0));

        localFileHeader.setCompressedSize(rawIO.readLongLittleEndian(inputStream, 4));
        localFileHeader.setUncompressedSize(rawIO.readLongLittleEndian(inputStream, 4));

        final int fileNameLength = rawIO.readShortLittleEndian(inputStream);
        localFileHeader.setFileNameLength(fileNameLength);

        localFileHeader.setExtraFieldLength(rawIO.readShortLittleEndian(inputStream));

        if (fileNameLength > 0)
        {
            final byte[] fileNameBuf = new byte[fileNameLength];
            readFully(inputStream, fileNameBuf);

            final String fileName = decodeStringWithCharset(fileNameBuf, localFileHeader.isFileNameUTF8Encoded(), charset);
            localFileHeader.setFileName(fileName);
            localFileHeader.setDirectory(fileName.endsWith("/") || fileName.endsWith("\\"));
        }
        else
        {
            throw new ZipException("Invalid entry name in local file header");
        }

        readExtraDataRecords(inputStream, localFileHeader);
        readZip64ExtendedInfo(localFileHeader, rawIO);
        readAesExtraDataRecord(localFileHeader, rawIO);

        if (localFileHeader.isEncrypted())
        {

            if (localFileHeader.getEncryptionMethod() == EncryptionMethod.AES)
            {
                // Do nothing
            }
            else
            {
                if (isBitSet(localFileHeader.getGeneralPurposeFlag()[0], 6))
                {
                    localFileHeader.setEncryptionMethod(EncryptionMethod.ZIP_STANDARD_VARIANT_STRONG);
                }
                else
                {
                    localFileHeader.setEncryptionMethod(EncryptionMethod.ZIP_STANDARD);
                }
            }

        }

        return localFileHeader;
    }


    public DataDescriptor readDataDescriptor(final InputStream inputStream, final boolean isZip64Format) throws IOException
    {

        final DataDescriptor dataDescriptor = new DataDescriptor();

        final byte[] intBuff = new byte[4];
        readFully(inputStream, intBuff);
        final long sigOrCrc = rawIO.readLongLittleEndian(intBuff, 0);

        // According to zip specification, presence of extra data record header
        // signature is optional.
        // If this signature is present, read it and read the next 4 bytes for
        // crc
        // If signature not present, assign the read 4 bytes for crc
        if (sigOrCrc == HeaderSignature.EXTRA_DATA_RECORD.getValue())
        {
            dataDescriptor.setSignature(HeaderSignature.EXTRA_DATA_RECORD);
            readFully(inputStream, intBuff);
            dataDescriptor.setCrc(rawIO.readLongLittleEndian(intBuff, 0));
        }
        else
        {
            dataDescriptor.setCrc(sigOrCrc);
        }

        if (isZip64Format)
        {
            dataDescriptor.setCompressedSize(rawIO.readLongLittleEndian(inputStream));
            dataDescriptor.setUncompressedSize(rawIO.readLongLittleEndian(inputStream));
        }
        else
        {
            dataDescriptor.setCompressedSize(rawIO.readIntLittleEndian(inputStream));
            dataDescriptor.setUncompressedSize(rawIO.readIntLittleEndian(inputStream));
        }

        return dataDescriptor;
    }


    private void readAesExtraDataRecord(final AbstractFileHeader fileHeader, final RawIO rawIO) throws ZipException
    {
        if (fileHeader.getExtraDataRecords() == null || fileHeader.getExtraDataRecords().size() <= 0)
        {
            return;
        }

        final AESExtraDataRecord aesExtraDataRecord = readAesExtraDataRecord(fileHeader.getExtraDataRecords(), rawIO);
        if (aesExtraDataRecord != null)
        {
            fileHeader.setAesExtraDataRecord(aesExtraDataRecord);
            fileHeader.setEncryptionMethod(EncryptionMethod.AES);
        }
    }


    private AESExtraDataRecord readAesExtraDataRecord(final List<ExtraDataRecord> extraDataRecords, final RawIO rawIO)
            throws ZipException
    {

        if (extraDataRecords == null)
        {
            return null;
        }

        for (final ExtraDataRecord extraDataRecord : extraDataRecords)
        {
            if (extraDataRecord == null)
            {
                continue;
            }

            if (extraDataRecord.getHeader() == HeaderSignature.AES_EXTRA_DATA_RECORD.getValue())
            {

                final byte[] aesExtraDataRecordBytes = extraDataRecord.getData();
                if (aesExtraDataRecordBytes == null || aesExtraDataRecordBytes.length != 7)
                {
                    throw new ZipException("corrupt AES extra data records");
                }

                final AESExtraDataRecord aesExtraDataRecord = new AESExtraDataRecord();

                aesExtraDataRecord.setSignature(HeaderSignature.AES_EXTRA_DATA_RECORD);
                aesExtraDataRecord.setDataSize(extraDataRecord.getSizeOfData());

                final byte[] aesData = extraDataRecord.getData();
                aesExtraDataRecord.setAesVersion(AesVersion.getFromVersionNumber(rawIO.readShortLittleEndian(aesData, 0)));
                final byte[] vendorIDBytes = new byte[2];
                System.arraycopy(aesData, 2, vendorIDBytes, 0, 2);
                aesExtraDataRecord.setVendorID(new String(vendorIDBytes));
                aesExtraDataRecord.setAesKeyStrength(AesKeyStrength.getAesKeyStrengthFromRawCode(aesData[4] & 0xFF));
                aesExtraDataRecord.setCompressionMethod(
                        CompressionMethod.getCompressionMethodFromCode(rawIO.readShortLittleEndian(aesData, 5)));

                return aesExtraDataRecord;
            }
        }

        return null;
    }


    private long getNumberOfEntriesInCentralDirectory(final ZipModel zipModel)
    {
        if (zipModel.isZip64Format())
        {
            return zipModel.getZip64EndOfCentralDirectoryRecord().getTotalNumberOfEntriesInCentralDirectory();
        }

        return zipModel.getEndOfCentralDirectoryRecord().getTotalNumberOfEntriesInCentralDirectory();
    }


    private long locateOffsetOfEndOfCentralDirectory(final RandomAccessFile randomAccessFile) throws IOException
    {
        final long zipFileSize = randomAccessFile.length();
        if (zipFileSize < ENDHDR)
        {
            throw new ZipException("Zip file size less than size of zip headers. Probably not a zip file.");
        }

        seekInCurrentPart(randomAccessFile, zipFileSize - ENDHDR);
        if (rawIO.readIntLittleEndian(randomAccessFile) == HeaderSignature.END_OF_CENTRAL_DIRECTORY.getValue())
        {
            return zipFileSize - ENDHDR;
        }

        return locateOffsetOfEndOfCentralDirectoryByReverseSeek(randomAccessFile);
    }


    private long locateOffsetOfEndOfCentralDirectoryByReverseSeek(final RandomAccessFile randomAccessFile) throws IOException
    {
        long currentFilePointer = randomAccessFile.length() - ENDHDR;
        // reverse seek for a maximum of MAX_COMMENT_SIZE bytes
        long numberOfBytesToRead = randomAccessFile.length() < MAX_COMMENT_SIZE ? randomAccessFile.length() : MAX_COMMENT_SIZE;

        while (numberOfBytesToRead > 0 && currentFilePointer > 0)
        {
            seekInCurrentPart(randomAccessFile, --currentFilePointer);
            if (rawIO.readIntLittleEndian(randomAccessFile) == HeaderSignature.END_OF_CENTRAL_DIRECTORY.getValue())
            {
                return currentFilePointer;
            }
            numberOfBytesToRead--;
        }
        ;

        throw new ZipException("Zip headers not found. Probably not a zip file");
    }


    private void seekInCurrentPart(final RandomAccessFile randomAccessFile, final long pos) throws IOException
    {
        if (randomAccessFile instanceof NumberedSplitRandomAccessFile)
        {
            ((NumberedSplitRandomAccessFile) randomAccessFile).seekInCurrentPart(pos);
        }
        else
        {
            randomAccessFile.seek(pos);
        }
    }


    private String readZipComment(final RandomAccessFile raf, final int commentLength, final Charset charset)
    {
        if (commentLength <= 0)
        {
            return null;
        }

        try
        {
            final byte[] commentBuf = new byte[commentLength];
            raf.readFully(commentBuf);
            return decodeStringWithCharset(commentBuf, false, charset != null ? charset : ZIP4J_DEFAULT_CHARSET);
        }
        catch (final IOException e)
        {
            // Ignore any exception and set comment to null if comment cannot be
            // read
            return null;
        }
    }


    public boolean isDirectory(final byte[] externalFileAttributes, final String fileName)
    {
        // first check if DOS attributes are set (lower order bytes from
        // external attributes). If yes, check if the 4th bit
        // which represents a directory is set. If UNIX attributes are set
        // (higher order two bytes), check for the 6th bit
        // in 4th byte which represents a directory flag.
        if (externalFileAttributes[0] != 0 && isBitSet(externalFileAttributes[0], 4))
        {
            return true;
        }
        else if (externalFileAttributes[3] != 0 && isBitSet(externalFileAttributes[3], 6))
        {
            return true;
        }

        return fileName != null && (fileName.endsWith("/") || fileName.endsWith("\\"));
    }
}
