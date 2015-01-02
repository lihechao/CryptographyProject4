/************************************************************************/
/*                          �򻯵�AES�ӽ����㷨							*/
/************************************************************************/
#include "stdafx.h"
#include "S-AES.h"
void main()
{
	printf("\t\t��������������S-AES�ӽ��ܹ��ߡ�������������\n\n");
	while(1)
	{
		char OpNum=0,FileName[256]="";
		BYTE PlainText[2]={0},Key[2]={0},RoundKey[6]={0},CipherText[2]={0};
		FILE *PlainFile=NULL,*CipherFile=NULL;
		printf("\n����������ţ�1-����һ������ 2-�����ļ� 3-����һ������ 4-�����ļ� 5-�˳�\n");
		do 
		{
			OpNum=getch();
		}while (!(OpNum>='1'&&OpNum<='5'));
		switch(OpNum)
		{
		case '1':
			printf("\n������16λ���ģ�ʮ�����Ƹ�ʽ����λ���Կհ��ַ��ָ���:\n");
			fflush(stdin);
			while (!scanf("%x%x",&PlainText[0],&PlainText[1]))
			{
				printf("\n������������������������룺\n");
				fflush(stdin);
			}
			printf("\n������16λ��Կ��ʮ�����Ƹ�ʽ����λ���Կհ��ַ��ָ���:\n");
			fflush(stdin);
			while (!scanf("%x%x",&Key[0],&Key[1]))
			{
				printf("\n���������Կ�������������룺\n");
				fflush(stdin);
			}
			Extend_Key(Key,RoundKey);
			EncryptBlock(PlainText,RoundKey,CipherText);
			printf("\n���ܺ������Ϊ��%X %X\n",CipherText[0],CipherText[1]);
			break;
		case '2':
			printf("\n������Ҫ���ܵ��ļ�����������չ������\n");
			scanf("%s",FileName);
			while(NULL==(PlainFile=fopen(FileName,"rb")))
			{
				fflush(stdin);
				printf("\n���ļ�ʧ�ܣ���ȷ���ļ��������ͬһĿ¼�¡�\n\n���������ļ�����\n");
				scanf("%s",FileName);
			}
			printf("\n������Ҫ���������ļ�����������չ������\n");
			scanf("%s",FileName);
			while(NULL==(CipherFile=fopen(FileName,"wb")))
			{
				fflush(stdin);
				printf("\n�����ļ�ʧ�ܣ����������ļ�����\n");
				scanf("%s",FileName);
			}
			printf("\n������16λ��Կ��ʮ�����Ƹ�ʽ����λ���Կհ��ַ��ָ���:\n");
			while (!scanf("%x%x",&Key[0],&Key[1]))
			{
				printf("\n���������Կ�������������룺\n");
				fflush(stdin);
			}
			EncryptFile(PlainFile,Key,CipherFile);
			printf("\n���ܺ�Ľ���������%s�ļ��С�\n",FileName);
			fclose(PlainFile);
			fclose(CipherFile);
			break;
		case '3':
			printf("\n������16λ���ģ�ʮ�����Ƹ�ʽ����λ���Կհ��ַ��ָ���:\n");
			fflush(stdin);
			while (!scanf("%x%x",&CipherText[0],&CipherText[1]))
			{
				printf("\n������������������������룺\n");
				fflush(stdin);
			}
			printf("\n������16λ��Կ��ʮ�����Ƹ�ʽ����λ���Կհ��ַ��ָ���:\n");
			fflush(stdin);
			while (!scanf("%x%x",&Key[0],&Key[1]))
			{
				printf("\n���������Կ�������������룺\n");
				fflush(stdin);
			}
			Extend_Key(Key,RoundKey);
			DecryptBlock(CipherText,RoundKey,PlainText);
			printf("\n���ܺ������Ϊ��%X %X\n",PlainText[0],PlainText[1]);
			break;
		case '4':
			printf("\n������Ҫ���ܵ��ļ�����������չ������\n");
			scanf("%s",FileName);
			while(NULL==(PlainFile=fopen(FileName,"rb")))
			{
				fflush(stdin);
				printf("\n���ļ�ʧ�ܣ���ȷ���ļ��������ͬһĿ¼�¡�\n\n���������ļ�����\n");
				scanf("%s",FileName);
			}
			printf("\n������Ҫ���������ļ�����������չ������\n");
			scanf("%s",FileName);
			while(NULL==(CipherFile=fopen(FileName,"wb")))
			{
				fflush(stdin);
				printf("\n�����ļ�ʧ�ܣ����������ļ�����\n");
				scanf("%s",FileName);
			}
			printf("\n������16λ��Կ��ʮ�����Ƹ�ʽ����λ���Կհ��ַ��ָ���:\n");
			while (!scanf("%x%x",&Key[0],&Key[1]))
			{
				printf("\n���������Կ�������������룺\n");
				fflush(stdin);
			}
			DecryptFile(PlainFile,Key,CipherFile);
			printf("\n���ܺ�Ľ���������%s�ļ��С�\n",FileName);
			fclose(PlainFile);
			fclose(CipherFile);
			break;
		case '5':
			exit(0);
			break;
		default:
			break;
		}
	}
}
/************************************************************************/
/*	�������ܣ���16λ��ʼ��Կ(����8λ����)��չ��48λ(6����)
	����˵����const BYTE Key[2] 16λ�ĳ�ʼ��Կ
			 BYTE RoundKey[6] �õ���48λ����Կ	*/
/************************************************************************/
void Extend_Key(const BYTE Key[2],BYTE RoundKey[6])/*��Կ��չ*/
{
	BYTE i;
	memcpy(RoundKey,Key,2*sizeof(BYTE));/*��Կ��ǰ2���ּ�Ϊ��ʼ��Կ*/
	for (i=2;i<6;i+=2)
	{
		RoundKey[i]=RoundKey[i-2]^RCon[i/2-1]^SubNib(ByteRol(RoundKey[i-1],4));
		RoundKey[i+1]=RoundKey[i]^RoundKey[i-1];
	}
}

/************************************************************************/
/*	�������ܣ���һ���ֽ��ڽ���ѭ�����ƣ�������Կ��չ��
	����˵����BYTE Byte Ҫ������λ���ֽ�����
			 BYTE Times ѭ�����ƴ���		*/
/************************************************************************/
BYTE ByteRol(BYTE Byte,BYTE Times)
{
	BYTE i,temp=0;/*�����Ƴ���λ*/
	for (i=0;i<Times;i++)
	{
		temp=(Byte&0x80)>>7;/*��ȡ��ByteҪ�Ƴ������λ���ŵ�temp�����λ*/
		Byte<<=1;/*Byte����һλ*/
		Byte|=temp;/*�Ƴ������λ�����λ*/
	}
	return Byte;/*���ؽ��*/
}

/************************************************************************/
/*	�������ܣ���Կ��չ�ж�һ���ֽ����ݽ����ֽڴ���
	����˵����BYTE Byte Ҫ�����ֽڴ�����ֽ�����		*/
/************************************************************************/
BYTE SubNib(BYTE Byte)
{
	return SBox[Byte>>6][(Byte>>4)&0x03]<<4|SBox[Byte>>2&0x03][Byte&0x03];
}

/************************************************************************/
/*	�������ܣ�����Կ�Ӻ���
	����˵����HALFBYTE State[2][2] Ҫ��������Կ�ӵľ���
			 const BYTE RoundKey[] ����Կ
			 BYTE RoundNum ����������ȷ��ѡ���ĸ�����Կ	*/
/************************************************************************/
void AddRoundKey(HALFBYTE State[2][2],const BYTE RoundKey[],BYTE RoundNum)
{
	State[0][0]=State[0][0]^(RoundKey[RoundNum*2]>>4);
	State[1][0]=State[1][0]^(RoundKey[RoundNum*2]&0x0F);
	State[0][1]=State[0][1]^(RoundKey[RoundNum*2+1]>>4);
	State[1][1]=State[1][1]^(RoundKey[RoundNum*2+1]&0x0F);
}

/************************************************************************/
/*	�������ܣ����ֽڴ���
	����˵����HALFBYTE State[2][2] Ҫ���а��ֽڴ���ľ���
			 const HALFBYTE Table[4][4] ���ұ���ΪSBoxʱ�����任��
										��ΪSBox_Invʱ����任	*/
/************************************************************************/
void SubHalfByte(HALFBYTE State[2][2],const HALFBYTE Table[4][4])
{
	State[0][0]=Table[State[0][0]>>2][State[0][0]&0x03];
	State[0][1]=Table[State[0][1]>>2][State[0][1]&0x03];
	State[1][0]=Table[State[1][0]>>2][State[1][0]&0x03];
	State[1][1]=Table[State[1][1]>>2][State[1][1]&0x03];
}

/************************************************************************/
/*	�������ܣ�����λ
	����˵����HALFBYTE State[2][2] Ҫ������λ�ľ���	*/
/************************************************************************/
void ShiftRows(HALFBYTE State[2][2])	/*����λ����һ�в��䣬�ڶ��н��а��ֽڵ�ѭ����λ*/
{
	State[1][0]^=State[1][1];/*�൱�ڵڶ��е�����������*/
	State[1][1]^=State[1][0];
	State[1][0]^=State[1][1];
}

/************************************************************************/
/*	�������ܣ��л���
	����˵����HALFBYTE State[2][2] Ҫ�����л����ľ���		*/
/************************************************************************/
void MixColumns(HALFBYTE State[2][2])
{
	HALFBYTE temp=State[0][0];
	State[0][0]^=(MultiplyTable[4][State[1][0]]);
	State[1][0]^=(MultiplyTable[4][temp]);
	temp=State[0][1];
	State[0][1]^=(MultiplyTable[4][State[1][1]]);
	State[1][1]^=(MultiplyTable[4][temp]);
}

/************************************************************************/
/*	�������ܣ������л���
	����˵����HALFBYTE State[2][2] Ҫ���������л����ľ���		*/
/************************************************************************/
void MixColumnsInverse(HALFBYTE State[2][2])
{
	HALFBYTE temp=State[0][0];
	State[0][0]=(MultiplyTable[9][State[0][0]]^MultiplyTable[2][State[1][0]]);
	State[1][0]=(MultiplyTable[9][State[1][0]]^MultiplyTable[2][temp]);
	temp=State[0][1];
	State[0][1]=(MultiplyTable[9][State[0][1]]^MultiplyTable[2][State[1][1]]);
	State[1][1]=(MultiplyTable[9][State[1][1]]^MultiplyTable[2][temp]);

}

/************************************************************************/
/*	�������ܣ�����һ�����飨16λ������
	����˵����const BYTE PlainText[2] Ҫ���м��ܵ����ķ���
			 const BYTE RoundKey[6] ���м����õ�����Կ
			 BYTE CipherText[2] ���ܺ�����Ľ��			*/
/************************************************************************/
void EncryptBlock(const BYTE PlainText[2],const BYTE RoundKey[6],BYTE CipherText[2])
{
	HALFBYTE State[2][2];
	State[0][0]=PlainText[0]>>4;/*ȡ����λ*/
	State[1][0]=PlainText[0]&0x0F;/*ȡ����λ*/
	State[0][1]=PlainText[1]>>4;
	State[1][1]=PlainText[1]&0x0F;

	AddRoundKey(State,RoundKey,0);/*����Կ��*/

	SubHalfByte(State,SBox);/*���ֽڴ���*/
	ShiftRows(State);/*����λ*/
	MixColumns(State);/*�л���*/
	AddRoundKey(State,RoundKey,1);/*����Կ��*/
 
	SubHalfByte(State,SBox);/*���ֽڴ���*/
	ShiftRows(State);/*����λ*/
	AddRoundKey(State,RoundKey,2);/*����Կ��*/

	CipherText[0]=State[0][0]<<4|State[1][0];/*�ĸ����ֽ�ת��Ϊ�����ֽ�*/
	CipherText[1]=State[0][1]<<4|State[1][1];
}

/************************************************************************/
/*	�������ܣ�����һ�����飨16λ������
	����˵����const BYTE CipherText[2] Ҫ���н��ܵ����ķ���
			 const BYTE RoundKey[6] ���н����õ�����Կ
			 BYTE CipherText[2] ���ܺ�����Ľ��			*/
/************************************************************************/
void DecryptBlock(const BYTE CipherText[2],const BYTE RoundKey[6],BYTE PlainText[2])
{
	HALFBYTE State[2][2]={0};
	State[0][0]=CipherText[0]>>4;/*ȡ����λ*/
	State[1][0]=CipherText[0]&0x0F;/*ȡ����λ*/
	State[0][1]=CipherText[1]>>4;
	State[1][1]=CipherText[1]&0x0F;

	AddRoundKey(State,RoundKey,2);

	ShiftRows(State);
	SubHalfByte(State,SBox_Inv);
	AddRoundKey(State,RoundKey,1);
	MixColumnsInverse(State);

	ShiftRows(State);
	SubHalfByte(State,SBox_Inv);
	AddRoundKey(State,RoundKey,0);

	PlainText[0]=State[0][0]<<4|State[1][0];
	PlainText[1]=State[0][1]<<4|State[1][1];
}

/************************************************************************/
/*	�������ܣ����ļ����м���
	����˵����FILE *PlainFile �������ڵ��ļ�ָ��
			 const BYTE Key[2] ����ĳ�ʼ��Կ
			 FILE *CipherFile ���ܺ����������ļ�ָ��	*/
/************************************************************************/
void EncryptFile(FILE *PlainFile,const BYTE Key[2],FILE *CipherFile)
{
	BYTE PlainText[2]={0},CipherText[2]={0},RoundKey[6]={0};
	int count=0;
	Extend_Key(Key,RoundKey);
	while (!feof(PlainFile))
	{
		if(2==(count=fread(PlainText,sizeof(BYTE),2,PlainFile)))
		{
			EncryptBlock(PlainText,RoundKey,CipherText);
			fwrite(CipherText,sizeof(BYTE),2,CipherFile);
		}
	}
	if (count)/*˵�����ĳ��Ȳ���2�ı�������Ҫ�����β*/
	{
		memset(PlainText+count,'\0',1);
		EncryptBlock(PlainText,RoundKey,CipherText);
		fwrite(CipherText,sizeof(BYTE),2,CipherFile);
	}
}

/************************************************************************/
/*	�������ܣ����ļ����н���
	����˵����FILE *CipherFile �������ڵ��ļ�ָ��
			 const BYTE Key[2] ����ĳ�ʼ��Կ
			 FILE *PlainFile ���ܺ����������ļ�ָ��	*/
/************************************************************************/
void DecryptFile(FILE *CipherFile,const BYTE Key[2],FILE *PlainFile)
{
	BYTE CipherText[2]={0},RoundKey[6]={0},PlainText[2]={0};
	Extend_Key(Key,RoundKey);
	while(!feof(CipherFile))
	{
		if (2==fread(CipherText,sizeof(BYTE),2,CipherFile))
		{
			DecryptBlock(CipherText,RoundKey,PlainText);
			fwrite(PlainText,sizeof(BYTE),2,PlainFile);
		}
	}
}