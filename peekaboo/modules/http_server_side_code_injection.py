class HTTP_SERVER_SIDE_CODE_INJECTION:

    def name(self):
        return 'HTTP_SERVER_SIDE_CODE_INJECTION'

    def selected(self, target):
        self.target = target
        
    def run(self):
        print(f'{self.target.ip_addr}')
        print('asdasdasd')
        print('richard is gay')
        print('evan is cool')
        
