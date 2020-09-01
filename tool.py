import sys
import struct
import numpy
import matplotlib.pyplot as plt
import optparse

from PIL import Image

from crypt import AESCipher

# convert binary to bits
def binary_to_bits(data):
	bitsoffile = []

	# Pack file len in 4 bytes
	filleSize = len(data)
	bytes = [ord(b) for b in struct.pack("i", filleSize)]

	bytes = bytes + [ord(b) for b in data]

	for b in bytes:
		for i in range(7, -1, -1):
			bitsoffile.append((b >> i) & 0x1)

	return bitsoffile


def bits_to_binary(bitsoffile):
	bytes = ""

	l = len(bitsoffile)
	for idx in range(0, len(bitsoffile)/8):
		byte = 0
		for i in range(0, 8):
			if (idx*8+i < l):
				byte = (byte<<1) + bitsoffile[idx*8+i]
		bytes = bytes + chr(byte)

	secrettext_size = struct.unpack("i", bytes[:4])[0]

	return bytes[4: secrettext_size + 4]

# Set the i-th bit of v to x
def set_bit(n, i, x):
	m = 1 << i
	n &= ~m
	if x:
		n |= m
	return n

# Hide text file into LSB bits of a source_image
def hide_text(sourceImg, secrettext, password):
	# Process source image
	img = Image.open(sourceImg)
	(width, height) = img.size
	conv_image = img.convert("RGBA").getdata()

	max_size = width*height*3.0/8/1024

	f = open(secrettext, "rb")
	data = f.read()
	f.close()


	cipher = AESCipher(password)
	data_enc = cipher.encrypt(data)

	# Process data from secrettext
	bitsoffile = binary_to_bits(data_enc)

	# Add until multiple of 3
	while(len(bitsoffile)%3):
		bitsoffile.append(0)

	secrettext_size = len(bitsoffile)/8/1024.0

	if (secrettext_size > max_size - 4):
		print "\n>>> Failed to hide the text, file is too large.\n"
		sys.exit()

	# Create output image
	steg_img = Image.new('RGBA',(width, height))
	data_img = steg_img.getdata()

	v = 0

	for h in range(height):
		for w in range(width):
			(r, g, b, a) = conv_image.getpixel((w, h))
			if v < len(bitsoffile):
				r = set_bit(r, 0, bitsoffile[v])
				g = set_bit(g, 0, bitsoffile[v+1])
				b = set_bit(b, 0, bitsoffile[v+2])
			data_img.putpixel((w,h), (r, g, b, a))
			v = v + 3

	steg_img.save("stego.png", "PNG")

	print "\n>> %s hidden successfully in the source file!\n" % secrettext

# Extract data hidden into LSB of the input file
def extract(inputf, outputf, password):
	# Process source image
	img = Image.open(inputf)
	(width, height) = img.size
	conv_image = img.convert("RGBA").getdata()


	# Extract LSBs
	v = []
	for h in range(height):
		for w in range(width):
			(r, g, b, a) = conv_image.getpixel((w, h))
			v.append(r & 1)                             #it will only append the lsb of each pixel
			v.append(g & 1)
			v.append(b & 1)

	data_out = bits_to_binary(v)

	# Decrypt
	cipher = AESCipher(password)
	data_dec = cipher.decrypt(data_out)

	# Write decrypted data
	out_f = open(outputf, "wb")
	out_f.write(data_dec)
	out_f.close()

	print ">> Data extracted from stego.png to %s." % outputf

# Statistical analysis of an image to detect LSB steganography
def analyse(inputf):

	BlkSize = 100	# Block size
	img = Image.open(inputf)
	(width, height) = img.size

	conv_image = img.convert("RGBA").getdata()

	# Extract LSBs
	vr = []	# Red LSBs
	vg = []	# Green LSBs
	vb = []	# LSBs
	for h in range(height):
		for w in range(width):
			(r, g, b, a) = conv_image.getpixel((w, h))
			vr.append(r & 1)
			vg.append(g & 1)
			vb.append(b & 1)

	# Average colours' LSB per each block
	avgR = []
	avgG = []
	avgB = []
	for i in range(0, len(vr), BlkSize):
		avgR.append(numpy.mean(vr[i:i + BlkSize]))
		avgG.append(numpy.mean(vg[i:i + BlkSize]))
		avgB.append(numpy.mean(vb[i:i + BlkSize]))

	# Plot using matplotlib to show the average lsb value per block to compare source and stego image
	numBlocks = len(avgR)
	blocks = [i for i in range(0, numBlocks)]
	plt.axis([0, len(avgR), 0, 1])
	plt.ylabel('Average LSB per block')
	plt.xlabel('Block number')

#	plt.plot(blocks, avgR, 'r.')
#	plt.plot(blocks, avgG, 'g')
	plt.plot(blocks, avgB, 'bo')

	plt.show()

def Main():

	    #Parser

        parser = optparse.OptionParser('usage %prog [option] [argument/image_file] \n'+\
		' -e to hide text in the image  \n -d to extract text from the image  \n -a to analyse the image ')
	parser.add_option('-e', dest='hide', type='string', \
		help='target picture path to hide text')
	parser.add_option('-d', dest='extr', type='string', \
		help='target picture path to retrieve text')
	parser.add_option('-a', dest='analyse', type='string', \
		help='target picture path to retrieve text')

	(options, args) = parser.parse_args()

	if (options.hide != None):                             #function call to hide text in image
		text1 = raw_input("Enter a filename to hide: ")
		textpass1 = raw_input("Enter a password:")
		hide_text(options.hide, text1, textpass1)

	elif (options.extr != None):                           #fuction call to extract the text from steg.image
		text2 = raw_input("Enter the name of text file to save the extracted data:")
		textpass2 = raw_input("Enter the password to decode:")
        	extract(options.extr, text2, textpass2)

	elif (options.analyse != None):                        #fuction call to analyse image
		analyse(options.analyse)

	else:
		print parser.usage
		exit(0)


if __name__ == '__main__':
	Main()
