#include "stdafx.h"
#include "S-AES.h"
void CrackKey(BYTE PlainText[2][2],BYTE CipherText[2][2],int Counter[4][16]);
int main()
{
	printf("\t\t��������������1��SAES���в�ֹ���������������\n\n");
label:while(1)
	  {
		  int i,j,k,l,Counter[4][16]={0};/*ÿ�����ֽڿ��ܵ�ֵ����������ֵԽ�������Խ��*/
		  int PossibleKeyNum[4]={0};/*�ĸ����ֽڷֱ���ܵ���Կ�����*/
		  HALFBYTE PossibleKey[4][2]={0};/*�ĸ����ֽ���Կ�Ŀ���ֵ��ÿ�����ֽ���������ֿ���*/
		  BYTE PlainText[2][2]={0},CipherText[2][2]={0};
		  BYTE Key[2]={0};/*�����ƽ������Կ*/
		  printf("\n�����������Ķԣ�ʮ�����Ƹ�ʽ����λ���Կհ��ַ��ָ�����AB CD��:\n");
		  printf("����1��");
		  while (!scanf("%x%x",&PlainText[0][0],&PlainText[0][1]))
		  {
			  fflush(stdin);
			  printf("������������������������룺\n����1��");
		  }
		  printf("����1��");
		  while (!scanf("%x%x",&CipherText[0][0],&CipherText[0][1]))
		  {
			  fflush(stdin);
			  printf("������������������������룺\n����1��");
		  }
		  printf("����2��");
		  while (!scanf("%x%x",&PlainText[1][0],&PlainText[1][1]))
		  {
			  fflush(stdin);
			  printf("������������������������룺\n����2��");
		  }
		  printf("����2��");
		  while (!scanf("%x%x",&CipherText[1][0],&CipherText[1][1]))
		  {
			  fflush(stdin);
			  printf("������������������������룺\n����2��");
		  }
		  CrackKey(PlainText,CipherText,Counter);
		  for (i=0;i<4;i++)
		  {
			  for (j=0;j<16;j++)
			  {
				  if (2==Counter[i][j])
				  {
					  PossibleKey[i][PossibleKeyNum[i]++]=j;
				  }
			  }
		  }
		  for (i=0;i<PossibleKeyNum[0];i++)/*�ӿ�����Կ������ȷ��Կ����ÿ�����ֽڵĿ���ֵƴ��һ���ĳ���ļ�������õ���Ӧ���ļ�Ϊ��ȷ*/
		  {
			  for (j=0;j<PossibleKeyNum[1];j++)
			  {
				  for (k=0;k<PossibleKeyNum[2];k++)
				  {
					  for (l=0;l<PossibleKeyNum[3];l++)
					  {
						  BYTE RoundKey[4],temp[2];
						  Key[0]=(PossibleKey[0][i]<<4)|(PossibleKey[1][j]);
						  Key[1]=(PossibleKey[2][k]<<4)|(PossibleKey[3][l]);
						  Extend_Key(Key,RoundKey);
						  EncryptBlock(PlainText[0],RoundKey,temp);
						  if (!memcmp(temp,CipherText[0],sizeof(BYTE)*2))
						  {
							  printf("�ƽ������ԿΪ��%X %X\n",Key[0],Key[1]);
							  goto label;/*�ƽ���ɼ��ɽ����´��ƽ�*/
						  }
					  }
				  }
			  }
		  }
		  printf("�ƽ�ʧ�ܣ����������Ķ��Ƿ��д�\n");
	  }
	  return 0;
}

/*******************************************************************/
/*�������ܣ���һ�������Ķ��ƽ���Կ�����ĸ����ֽ���Կ�Ŀ���ֵ��Ӧ������
������Counter�м�1
*/
/*******************************************************************/
void CrackKey(BYTE PlainText[2][2],BYTE CipherText[2][2],int Counter[4][16])
{
	BYTE CipherXor[2]={0},i;
	HALFBYTE State[2][2]={0};
	CipherXor[0]=CipherText[0][0]^CipherText[1][0];
	CipherXor[1]=CipherText[0][1]^CipherText[1][1];
	State[0][0]=CipherXor[0]>>4;/*ȡ����λ*/
	State[1][0]=CipherXor[0]&0x0F;/*ȡ����λ*/
	State[0][1]=CipherXor[1]>>4;
	State[1][1]=CipherXor[1]&0x0F;
	MixColumnsInverse(State);
	ShiftRows(State);
	for (i=0;i<=0x0F;i++)
	{
		if ((SBox_Inv[i>>2][i&0x03]^(PlainText[0][0]>>4))
			==(SBox_Inv[(i^State[0][0])>>2][(i^State[0][0])&0x03]^(PlainText[1][0]>>4)))
		{
			Counter[0][SBox_Inv[i>>2][i&0x03]^(PlainText[0][0]>>4)]++;
			Counter[0][SBox_Inv[i>>2][i&0x03]^(PlainText[1][0]>>4)]++;
		}
		if ((SBox_Inv[i>>2][i&0x03]^(PlainText[0][0]&0x0F))
			==(SBox_Inv[(i^State[1][0])>>2][(i^State[1][0])&0x03]^(PlainText[1][0]&0x0F)))
		{
			Counter[1][SBox_Inv[i>>2][i&0x03]^(PlainText[0][0]&0x0F)]++;
			Counter[1][SBox_Inv[i>>2][i&0x03]^(PlainText[1][0]&0x0F)]++;
		}
		if ((SBox_Inv[i>>2][i&0x03]^(PlainText[0][1]>>4))
			==(SBox_Inv[(i^State[0][1])>>2][(i^State[0][1])&0x03]^(PlainText[1][1]>>4)))
		{
			Counter[2][SBox_Inv[i>>2][i&0x03]^(PlainText[0][1]>>4)]++;
			Counter[2][SBox_Inv[i>>2][i&0x03]^(PlainText[1][1]>>4)]++;
		}
		if ((SBox_Inv[i>>2][i&0x03]^(PlainText[0][1]&0x0F))
			==(SBox_Inv[(i^State[1][1])>>2][(i^State[1][1])&0x03]^(PlainText[1][1]&0x0F)))
		{
			Counter[3][SBox_Inv[i>>2][i&0x03]^(PlainText[0][1]&0x0F)]++;
			Counter[3][SBox_Inv[i>>2][i&0x03]^(PlainText[1][1]&0x0F)]++;
		}
	}
}