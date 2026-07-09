pragma Warnings (Off);
pragma Ada_95;
pragma Source_File_Name (ada_main, Spec_File_Name => "b__check_release_ready.ads");
pragma Source_File_Name (ada_main, Body_File_Name => "b__check_release_ready.adb");
pragma Suppress (Overflow_Check);
with Ada.Exceptions;

package body ada_main is

   E075 : Short_Integer; pragma Import (Ada, E075, "system__os_lib_E");
   E011 : Short_Integer; pragma Import (Ada, E011, "ada__exceptions_E");
   E015 : Short_Integer; pragma Import (Ada, E015, "system__soft_links_E");
   E024 : Short_Integer; pragma Import (Ada, E024, "system__exception_table_E");
   E040 : Short_Integer; pragma Import (Ada, E040, "ada__containers_E");
   E070 : Short_Integer; pragma Import (Ada, E070, "ada__io_exceptions_E");
   E031 : Short_Integer; pragma Import (Ada, E031, "ada__numerics_E");
   E055 : Short_Integer; pragma Import (Ada, E055, "ada__strings_E");
   E057 : Short_Integer; pragma Import (Ada, E057, "ada__strings__maps_E");
   E060 : Short_Integer; pragma Import (Ada, E060, "ada__strings__maps__constants_E");
   E045 : Short_Integer; pragma Import (Ada, E045, "interfaces__c_E");
   E025 : Short_Integer; pragma Import (Ada, E025, "system__exceptions_E");
   E086 : Short_Integer; pragma Import (Ada, E086, "system__object_reader_E");
   E050 : Short_Integer; pragma Import (Ada, E050, "system__dwarf_lines_E");
   E017 : Short_Integer; pragma Import (Ada, E017, "system__soft_links__initialize_E");
   E039 : Short_Integer; pragma Import (Ada, E039, "system__traceback__symbolic_E");
   E111 : Short_Integer; pragma Import (Ada, E111, "ada__strings__utf_encoding_E");
   E119 : Short_Integer; pragma Import (Ada, E119, "ada__tags_E");
   E109 : Short_Integer; pragma Import (Ada, E109, "ada__strings__text_buffers_E");
   E191 : Short_Integer; pragma Import (Ada, E191, "gnat_E");
   E127 : Short_Integer; pragma Import (Ada, E127, "ada__streams_E");
   E143 : Short_Integer; pragma Import (Ada, E143, "system__file_control_block_E");
   E138 : Short_Integer; pragma Import (Ada, E138, "system__finalization_root_E");
   E136 : Short_Integer; pragma Import (Ada, E136, "ada__finalization_E");
   E135 : Short_Integer; pragma Import (Ada, E135, "system__file_io_E");
   E188 : Short_Integer; pragma Import (Ada, E188, "ada__streams__stream_io_E");
   E184 : Short_Integer; pragma Import (Ada, E184, "system__storage_pools_E");
   E204 : Short_Integer; pragma Import (Ada, E204, "system__storage_pools__subpools_E");
   E171 : Short_Integer; pragma Import (Ada, E171, "ada__strings__unbounded_E");
   E150 : Short_Integer; pragma Import (Ada, E150, "ada__calendar_E");
   E156 : Short_Integer; pragma Import (Ada, E156, "ada__calendar__time_zones_E");
   E125 : Short_Integer; pragma Import (Ada, E125, "ada__text_io_E");
   E200 : Short_Integer; pragma Import (Ada, E200, "system__pool_global_E");
   E182 : Short_Integer; pragma Import (Ada, E182, "system__regexp_E");
   E148 : Short_Integer; pragma Import (Ada, E148, "ada__directories_E");
   E194 : Short_Integer; pragma Import (Ada, E194, "project_tools__text_E");
   E186 : Short_Integer; pragma Import (Ada, E186, "project_tools__files_E");
   E146 : Short_Integer; pragma Import (Ada, E146, "project_tools__processes_E");

   Sec_Default_Sized_Stacks : array (1 .. 1) of aliased System.Secondary_Stack.SS_Stack (System.Parameters.Runtime_Default_Sec_Stack_Size);

   Local_Priority_Specific_Dispatching : constant String := "";
   Local_Interrupt_States : constant String := "";

   Is_Elaborated : Boolean := False;

   procedure finalize_library is
   begin
      declare
         procedure F1;
         pragma Import (Ada, F1, "project_tools__files__finalize_body");
      begin
         E186 := E186 - 1;
         F1;
      end;
      declare
         procedure F2;
         pragma Import (Ada, F2, "ada__directories__finalize_body");
      begin
         E148 := E148 - 1;
         F2;
      end;
      declare
         procedure F3;
         pragma Import (Ada, F3, "ada__directories__finalize_spec");
      begin
         F3;
      end;
      E182 := E182 - 1;
      declare
         procedure F4;
         pragma Import (Ada, F4, "system__regexp__finalize_spec");
      begin
         F4;
      end;
      E200 := E200 - 1;
      declare
         procedure F5;
         pragma Import (Ada, F5, "system__pool_global__finalize_spec");
      begin
         F5;
      end;
      E125 := E125 - 1;
      declare
         procedure F6;
         pragma Import (Ada, F6, "ada__text_io__finalize_spec");
      begin
         F6;
      end;
      E171 := E171 - 1;
      declare
         procedure F7;
         pragma Import (Ada, F7, "ada__strings__unbounded__finalize_spec");
      begin
         F7;
      end;
      E204 := E204 - 1;
      declare
         procedure F8;
         pragma Import (Ada, F8, "system__storage_pools__subpools__finalize_spec");
      begin
         F8;
      end;
      E188 := E188 - 1;
      declare
         procedure F9;
         pragma Import (Ada, F9, "ada__streams__stream_io__finalize_spec");
      begin
         F9;
      end;
      declare
         procedure F10;
         pragma Import (Ada, F10, "system__file_io__finalize_body");
      begin
         E135 := E135 - 1;
         F10;
      end;
      declare
         procedure Reraise_Library_Exception_If_Any;
            pragma Import (Ada, Reraise_Library_Exception_If_Any, "__gnat_reraise_library_exception_if_any");
      begin
         Reraise_Library_Exception_If_Any;
      end;
   end finalize_library;

   procedure adafinal is
      procedure s_stalib_adafinal;
      pragma Import (Ada, s_stalib_adafinal, "system__standard_library__adafinal");

      procedure Runtime_Finalize;
      pragma Import (C, Runtime_Finalize, "__gnat_runtime_finalize");

   begin
      if not Is_Elaborated then
         return;
      end if;
      Is_Elaborated := False;
      Runtime_Finalize;
      s_stalib_adafinal;
   end adafinal;

   type No_Param_Proc is access procedure;
   pragma Favor_Top_Level (No_Param_Proc);

   procedure adainit is
      Main_Priority : Integer;
      pragma Import (C, Main_Priority, "__gl_main_priority");
      Time_Slice_Value : Integer;
      pragma Import (C, Time_Slice_Value, "__gl_time_slice_val");
      WC_Encoding : Character;
      pragma Import (C, WC_Encoding, "__gl_wc_encoding");
      Locking_Policy : Character;
      pragma Import (C, Locking_Policy, "__gl_locking_policy");
      Queuing_Policy : Character;
      pragma Import (C, Queuing_Policy, "__gl_queuing_policy");
      Task_Dispatching_Policy : Character;
      pragma Import (C, Task_Dispatching_Policy, "__gl_task_dispatching_policy");
      Priority_Specific_Dispatching : System.Address;
      pragma Import (C, Priority_Specific_Dispatching, "__gl_priority_specific_dispatching");
      Num_Specific_Dispatching : Integer;
      pragma Import (C, Num_Specific_Dispatching, "__gl_num_specific_dispatching");
      Main_CPU : Integer;
      pragma Import (C, Main_CPU, "__gl_main_cpu");
      Interrupt_States : System.Address;
      pragma Import (C, Interrupt_States, "__gl_interrupt_states");
      Num_Interrupt_States : Integer;
      pragma Import (C, Num_Interrupt_States, "__gl_num_interrupt_states");
      Unreserve_All_Interrupts : Integer;
      pragma Import (C, Unreserve_All_Interrupts, "__gl_unreserve_all_interrupts");
      Detect_Blocking : Integer;
      pragma Import (C, Detect_Blocking, "__gl_detect_blocking");
      Default_Stack_Size : Integer;
      pragma Import (C, Default_Stack_Size, "__gl_default_stack_size");
      Default_Secondary_Stack_Size : System.Parameters.Size_Type;
      pragma Import (C, Default_Secondary_Stack_Size, "__gnat_default_ss_size");
      Bind_Env_Addr : System.Address;
      pragma Import (C, Bind_Env_Addr, "__gl_bind_env_addr");
      Interrupts_Default_To_System : Integer;
      pragma Import (C, Interrupts_Default_To_System, "__gl_interrupts_default_to_system");

      procedure Runtime_Initialize (Install_Handler : Integer);
      pragma Import (C, Runtime_Initialize, "__gnat_runtime_initialize");

      Finalize_Library_Objects : No_Param_Proc;
      pragma Import (C, Finalize_Library_Objects, "__gnat_finalize_library_objects");
      Binder_Sec_Stacks_Count : Natural;
      pragma Import (Ada, Binder_Sec_Stacks_Count, "__gnat_binder_ss_count");
      Default_Sized_SS_Pool : System.Address;
      pragma Import (Ada, Default_Sized_SS_Pool, "__gnat_default_ss_pool");

   begin
      if Is_Elaborated then
         return;
      end if;
      Is_Elaborated := True;
      Main_Priority := -1;
      Time_Slice_Value := -1;
      WC_Encoding := 'b';
      Locking_Policy := ' ';
      Queuing_Policy := ' ';
      Task_Dispatching_Policy := ' ';
      Priority_Specific_Dispatching :=
        Local_Priority_Specific_Dispatching'Address;
      Num_Specific_Dispatching := 0;
      Main_CPU := -1;
      Interrupt_States := Local_Interrupt_States'Address;
      Num_Interrupt_States := 0;
      Unreserve_All_Interrupts := 0;
      Detect_Blocking := 0;
      Default_Stack_Size := -1;

      ada_main'Elab_Body;
      Default_Secondary_Stack_Size := System.Parameters.Runtime_Default_Sec_Stack_Size;
      Binder_Sec_Stacks_Count := 1;
      Default_Sized_SS_Pool := Sec_Default_Sized_Stacks'Address;

      Runtime_Initialize (1);

      Finalize_Library_Objects := finalize_library'access;

      Ada.Exceptions'Elab_Spec;
      System.Soft_Links'Elab_Spec;
      System.Exception_Table'Elab_Body;
      E024 := E024 + 1;
      Ada.Containers'Elab_Spec;
      E040 := E040 + 1;
      Ada.Io_Exceptions'Elab_Spec;
      E070 := E070 + 1;
      Ada.Numerics'Elab_Spec;
      E031 := E031 + 1;
      Ada.Strings'Elab_Spec;
      E055 := E055 + 1;
      Ada.Strings.Maps'Elab_Spec;
      E057 := E057 + 1;
      Ada.Strings.Maps.Constants'Elab_Spec;
      E060 := E060 + 1;
      Interfaces.C'Elab_Spec;
      E045 := E045 + 1;
      System.Exceptions'Elab_Spec;
      E025 := E025 + 1;
      System.Object_Reader'Elab_Spec;
      E086 := E086 + 1;
      System.Dwarf_Lines'Elab_Spec;
      E050 := E050 + 1;
      System.Os_Lib'Elab_Body;
      E075 := E075 + 1;
      System.Soft_Links.Initialize'Elab_Body;
      E017 := E017 + 1;
      E015 := E015 + 1;
      System.Traceback.Symbolic'Elab_Body;
      E039 := E039 + 1;
      E011 := E011 + 1;
      Ada.Strings.Utf_Encoding'Elab_Spec;
      E111 := E111 + 1;
      Ada.Tags'Elab_Spec;
      Ada.Tags'Elab_Body;
      E119 := E119 + 1;
      Ada.Strings.Text_Buffers'Elab_Spec;
      E109 := E109 + 1;
      Gnat'Elab_Spec;
      E191 := E191 + 1;
      Ada.Streams'Elab_Spec;
      E127 := E127 + 1;
      System.File_Control_Block'Elab_Spec;
      E143 := E143 + 1;
      System.Finalization_Root'Elab_Spec;
      E138 := E138 + 1;
      Ada.Finalization'Elab_Spec;
      E136 := E136 + 1;
      System.File_Io'Elab_Body;
      E135 := E135 + 1;
      Ada.Streams.Stream_Io'Elab_Spec;
      E188 := E188 + 1;
      System.Storage_Pools'Elab_Spec;
      E184 := E184 + 1;
      System.Storage_Pools.Subpools'Elab_Spec;
      E204 := E204 + 1;
      Ada.Strings.Unbounded'Elab_Spec;
      E171 := E171 + 1;
      Ada.Calendar'Elab_Spec;
      Ada.Calendar'Elab_Body;
      E150 := E150 + 1;
      Ada.Calendar.Time_Zones'Elab_Spec;
      E156 := E156 + 1;
      Ada.Text_Io'Elab_Spec;
      Ada.Text_Io'Elab_Body;
      E125 := E125 + 1;
      System.Pool_Global'Elab_Spec;
      E200 := E200 + 1;
      System.Regexp'Elab_Spec;
      E182 := E182 + 1;
      Ada.Directories'Elab_Spec;
      Ada.Directories'Elab_Body;
      E148 := E148 + 1;
      E194 := E194 + 1;
      Project_Tools.Files'Elab_Body;
      E186 := E186 + 1;
      E146 := E146 + 1;
   end adainit;

   procedure Ada_Main_Program;
   pragma Import (Ada, Ada_Main_Program, "_ada_check_release_ready");

   function main
     (argc : Integer;
      argv : System.Address;
      envp : System.Address)
      return Integer
   is
      procedure Initialize (Addr : System.Address);
      pragma Import (C, Initialize, "__gnat_initialize");

      procedure Finalize;
      pragma Import (C, Finalize, "__gnat_finalize");
      SEH : aliased array (1 .. 2) of Integer;

      Ensure_Reference : aliased System.Address := Ada_Main_Program_Name'Address;
      pragma Volatile (Ensure_Reference);

   begin
      if gnat_argc = 0 then
         gnat_argc := argc;
         gnat_argv := argv;
      end if;
      gnat_envp := envp;

      Initialize (SEH'Address);
      adainit;
      Ada_Main_Program;
      adafinal;
      Finalize;
      return (gnat_exit_status);
   end;

--  BEGIN Object file/option list
   --   /home/bent/Projekte/Ada/cryptolib/tools/obj/check_release_ready.o
   --   -L/home/bent/Projekte/Ada/cryptolib/tools/obj/
   --   -L/home/bent/Projekte/Ada/cryptolib/tools/obj/
   --   -L/home/bent/Projekte/Ada/cryptolib/lib/
   --   -L/home/bent/Projekte/Ada/project_tools/lib/
   --   -L/home/bent/.local/share/alire/toolchains/gnat_native_15.2.1_4640d4b3/lib/gcc/x86_64-pc-linux-gnu/15.2.0/adalib/
   --   -static
   --   -lgnat
   --   -ldl
--  END Object file/option list   

end ada_main;
